import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import json
import base64
import binascii
import hashlib
import hmac
import math
import secrets
from datetime import datetime

# ==========================================
# 1. ユーティリティ・データ処理関数
# ==========================================

DEFAULT_PASSWORD = "puca"
PASSWORD_HASH_ITERATIONS = 310_000


def encode_data(data_dict):
    json_str = json.dumps(data_dict, ensure_ascii=False, allow_nan=False)
    return base64.b64encode(json_str.encode("utf-8")).decode("ascii")


def decode_data(encoded_data):
    padded_data = encoded_data + "=" * (-len(encoded_data) % 4)
    try:
        json_str = base64.b64decode(padded_data, validate=True).decode("utf-8")
        data = json.loads(json_str)
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("バックアップデータを読み取れません。") from exc
    if not isinstance(data, dict):
        raise ValueError("バックアップデータの形式が正しくありません。")
    return data


def create_password_hash(password):
    salt = secrets.token_bytes(16)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PASSWORD_HASH_ITERATIONS,
    )
    return {
        "password_salt": salt.hex(),
        "password_hash": password_hash.hex(),
        "password_iterations": PASSWORD_HASH_ITERATIONS,
    }


def has_saved_password(user_db):
    account = user_db.get("tomato", {})
    return any(
        key in account
        for key in ("password_salt", "password_hash", "password_iterations")
    )


def verify_login(username, password, user_db):
    if username != "tomato":
        return False

    account = user_db.get("tomato", {})
    if not has_saved_password(user_db):
        return password == DEFAULT_PASSWORD

    try:
        salt = bytes.fromhex(account["password_salt"])
        expected_hash = bytes.fromhex(account["password_hash"])
        iterations = account["password_iterations"]
    except (KeyError, TypeError, ValueError):
        return False

    if (
        not isinstance(iterations, int)
        or isinstance(iterations, bool)
        or not 100_000 <= iterations <= 2_000_000
        or len(salt) != 16
        or len(expected_hash) != hashlib.sha256().digest_size
    ):
        return False

    actual_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
    )
    return hmac.compare_digest(actual_hash, expected_hash)


def build_save_payload(user_info):
    return {
        "user_db": user_info["user_db"],
        "records": user_info["data"],
    }


def normalize_user_db(user_db):
    if user_db is None:
        user_db = {}
    if not isinstance(user_db, dict):
        raise ValueError("ユーザー設定データの形式が正しくありません。")

    account = user_db.get("tomato", {})
    if not isinstance(account, dict):
        raise ValueError("ユーザー設定データの形式が正しくありません。")

    normalized_user_db = dict(user_db)
    normalized_account = dict(account)
    normalized_account.pop("password", None)
    normalized_user_db["tomato"] = normalized_account
    return normalized_user_db


def decode_text_with_fallback(raw_bytes):
    for encoding in ("utf-8-sig", "utf-8", "cp932", "shift_jis"):
        try:
            return raw_bytes.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw_bytes.decode("utf-8", errors="replace")


def parse_backup_csv(uploaded_file):
    if uploaded_file is None:
        return None
    text_data = decode_text_with_fallback(uploaded_file.getvalue()).replace("\r\n", "\n")
    for line in text_data.split("\n"):
        backup_line = line.strip()
        if backup_line.startswith("#BACKUP:"):
            return decode_data(backup_line.split("#BACKUP:", 1)[1].strip())
    return None


def normalize_records(records):
    if not isinstance(records, list):
        raise ValueError("記録データはリスト形式である必要があります。")

    normalized_records = []
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise ValueError(f"{index + 1}件目の記録形式が正しくありません。")

        normalized_record = dict(record)
        if normalized_record.get("fat_pct") is None and normalized_record.get("fat") is not None:
            normalized_record["fat_pct"] = normalized_record["fat"]
        normalized_record.pop("fat", None)

        if not normalized_record.get("date"):
            raise ValueError(f"{index + 1}件目の記録に日付がありません。")
        try:
            parsed_date = pd.to_datetime(normalized_record["date"], errors="raise")
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{index + 1}件目の日付が正しくありません。") from exc
        if pd.isna(parsed_date):
            raise ValueError(f"{index + 1}件目の日付が正しくありません。")
        normalized_record["date"] = parsed_date.date().isoformat()

        for column in ("weight", "bmi", "fat_pct", "visceral", "muscle", "water"):
            if column not in normalized_record:
                continue
            value = normalized_record[column]
            if isinstance(value, (dict, list, tuple, set, bool)):
                raise ValueError(
                    f"{index + 1}件目の「{column}」は単一の数値である必要があります。"
                )
            try:
                numeric_value = pd.to_numeric(value, errors="coerce")
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f"{index + 1}件目の「{column}」が数値として解釈できません。"
                ) from exc
            if pd.isna(numeric_value):
                normalized_record[column] = None
            else:
                numeric_value = float(numeric_value)
                if not math.isfinite(numeric_value):
                    raise ValueError(
                        f"{index + 1}件目の「{column}」は有限の数値ではありません。"
                    )
                normalized_record[column] = numeric_value

        normalized_records.append(normalized_record)
    return normalized_records


def numeric_series(frame, column):
    if column not in frame.columns:
        return pd.Series(float("nan"), index=frame.index, dtype="float64")
    return pd.to_numeric(frame[column], errors="coerce")


# ==========================================
# 2. メインアプリケーション設定
# ==========================================

st.set_page_config(page_title="BodyMetrics - 統合健康管理システム", layout="wide")
st.title("📊 BodyMetrics ／ 統合健康管理システム")

# トラブルの原因だった位置固定用のCSSを廃止し、文字サイズと余白の調整のみに限定
st.markdown("""
    <style>
    /* アプリ全体の基本文字 */
    html, body, [data-testid="stMarkdownContainer"] p {
        font-size: 1.15rem !important;
        line-height: 1.6 !important;
    }
    
    /* 見出し（本日の記録、履歴データなど） */
    h2, h3, .stSubheader {
        font-size: 1.65rem !important;
        font-weight: bold !important;
        color: #111111 !important;
        margin-bottom: 15px !important;
    }
    
    /* 入力項目のラベル文字 */
    .stNumberInput label, .stDateInput label, .stTextInput label {
        font-size: 1.15rem !important;
        font-weight: 700 !important;
        color: #222222 !important;
    }
    
    /* 入力枠内の数値・文字の大きさ */
    .stNumberInput input, .stDateInput input, .stTextInput input {
        font-size: 1.15rem !important;
        height: 48px !important;
        font-weight: bold !important;
    }
    
    /* バックアップ保存ボタンの調整 */
    .stButton button, .stDownloadButton button {
        font-size: 1.1rem !important;
        font-weight: bold !important;
        padding: 8px 20px !important;
        white-space: nowrap !important;
    }

    /* 本日の記録フォームの外枠 */
    .stForm {
        border-radius: 10px !important;
        padding: 20px !important;
        background-color: #fdfdfd !important;
        border: 2px solid #dbdbdb !important;
    }
    
    /* 履歴データのテーブル内の文字サイズ */
    [data-testid="stTable"] *, [data-testid="stDataFrame"] * {
        font-size: 1.25rem !important;
    }
    </style>
""", unsafe_allow_html=True)

# 新規サインイン用の初期データ。共有された最新JSONのrecordsをここに設定します。
initial_records = []

if "user" not in st.session_state:
    st.session_state.user = {}

is_logged_in = "username" in st.session_state.user
pending_records = None
pending_user_db = None
pending_restore_error = None

if not is_logged_in:
    saved_data = st.query_params.get("health_data", "")
    if saved_data:
        try:
            saved_payload = decode_data(saved_data)
            pending_user_db = normalize_user_db(saved_payload.get("user_db"))
        except (TypeError, ValueError) as exc:
            pending_restore_error = str(exc)

if not is_logged_in:
    st.subheader("ログイン / バックアップ復元")
    st.caption("健康データはURLにBase64形式で保存されます。暗号化ではないため、URLを他人と共有しないでください。")

    if pending_restore_error:
        st.error(f"URLに保存されたデータを復元できません: {pending_restore_error}")
    
    uploaded_file = st.file_uploader("バックアップCSVファイルをここにドラッグ＆ドロップ", type=["csv"])
    if uploaded_file is not None:
        try:
            restored = parse_backup_csv(uploaded_file)
            if restored is None or "records" not in restored:
                raise ValueError("CSVに有効な #BACKUP データがありません。")
            restored_records = normalize_records(restored["records"])
            restored_user_db = normalize_user_db(restored.get("user_db"))
            restored_user_db.setdefault(
                "tomato",
                {"height": 174.0, "target_weight": 65.0},
            )
            pending_records = restored_records
            pending_user_db = restored_user_db
            st.info("バックアップを読み込みました。ユーザー名とパスワードを入力して復元してください。")
        except (OSError, TypeError, ValueError) as exc:
            st.error(f"バックアップを復元できません: {exc}")

    with st.form("login"):
        user_input = st.text_input("ユーザー名", value="tomato")
        pass_input = st.text_input("パスワード", type="password")
        if st.form_submit_button("サインイン"):
            login_user_db = pending_user_db or {
                "tomato": {"height": 174.0, "target_weight": 65.0}
            }
            if not verify_login(user_input, pass_input, login_user_db):
                st.error("ユーザー名またはパスワードが正しくありません。")
            elif pending_restore_error:
                st.error("保存データを復元できないため、先にバックアップCSVを復元してください。")
            else:
                if not has_saved_password(login_user_db):
                    login_user_db["tomato"].update(
                        create_password_hash(DEFAULT_PASSWORD)
                    )
                st.session_state.user = {
                    "username": user_input,
                    "data": pending_records if pending_records is not None else [],
                    "user_db": login_user_db,
                }
                st.query_params["health_data"] = encode_data(
                    build_save_payload(st.session_state.user)
                )
                st.rerun()
else:
    user_info = st.session_state.user
    try:
        user_info["data"] = normalize_records(user_info.get("data", []))
        user_info["user_db"] = normalize_user_db(user_info.get("user_db"))
    except (TypeError, ValueError) as exc:
        st.error(f"保存データに不整合があります: {exc}")
        st.stop()
    st.sidebar.title(f"👤 {user_info['username']}")
    latest_record = max(
        user_info["data"],
        key=lambda record: record["date"],
        default={},
    )
    latest_record_key = hashlib.sha256(
        json.dumps(
            [
                latest_record.get(column)
                for column in (
                    "date",
                    "weight",
                    "bmi",
                    "fat_pct",
                    "visceral",
                    "muscle",
                    "water",
                )
            ],
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()[:12]

    def latest_measurement(column, default):
        value = latest_record.get(column)
        return default if value is None else value

    with st.sidebar.form("password_change_form"):
        new_password = st.text_input("新しいパスワード", type="password")
        confirm_password = st.text_input("新しいパスワード（確認）", type="password")
        if st.form_submit_button("パスワードを更新する"):
            if not new_password:
                st.error("新しいパスワードを入力してください。")
            elif new_password != confirm_password:
                st.error("新しいパスワードが一致しません。")
            else:
                user_info["user_db"].setdefault("tomato", {}).update(
                    create_password_hash(new_password)
                )
                st.session_state.user = user_info
                st.query_params["health_data"] = encode_data(
                    build_save_payload(user_info)
                )
                st.sidebar.success("パスワードを更新しました。")
    
    if st.sidebar.button("サインアウト"):
        st.session_state.user = {}
        st.rerun()

    # 【確実なレイアウト修正】「本日の記録」側を細め（2）に固定し、「履歴データ」側を広め（3）に指定
    col1, col2 = st.columns([1.8, 3.2])
    
    with col1:
        st.subheader("本日の記録")
        with st.form("input_form"):
            date_label, date_input = st.columns([1, 2])
            with date_label:
                st.markdown("<div style='height: 48px; display: flex; align-items: center; font-weight: 700'>日付</div>", unsafe_allow_html=True)
            with date_input:
                d = st.date_input("日付", datetime.today(), label_visibility="collapsed")

            weight_label, weight_input = st.columns([1, 2])
            with weight_label:
                st.markdown("<div style='height: 48px; display: flex; align-items: center; font-weight: 700'>体重 (kg)</div>", unsafe_allow_html=True)
            with weight_input:
                w = st.number_input("体重 (kg)", value=latest_measurement("weight", 70.0), step=0.05, format="%.2f", label_visibility="collapsed", key=f"weight_{latest_record_key}")

            bmi_label, bmi_input = st.columns([1, 2])
            with bmi_label:
                st.markdown("<div style='height: 48px; display: flex; align-items: center; font-weight: 700'>BMI</div>", unsafe_allow_html=True)
            with bmi_input:
                b = st.number_input("BMI", value=latest_measurement("bmi", 22.0), step=0.05, format="%.2f", label_visibility="collapsed", key=f"bmi_{latest_record_key}")

            fat_label, fat_input = st.columns([1, 2])
            with fat_label:
                st.markdown("<div style='height: 48px; display: flex; align-items: center; font-weight: 700'>体脂肪率 (%)</div>", unsafe_allow_html=True)
            with fat_input:
                f = st.number_input("体脂肪率 (%)", value=latest_measurement("fat_pct", 20.0), step=0.05, format="%.2f", label_visibility="collapsed", key=f"fat_{latest_record_key}")

            visceral_label, visceral_input = st.columns([1, 2])
            with visceral_label:
                st.markdown("<div style='height: 48px; display: flex; align-items: center; font-weight: 700'>内臓脂肪レベル</div>", unsafe_allow_html=True)
            with visceral_input:
                v = st.number_input("内臓脂肪レベル", value=latest_measurement("visceral", 5.0), step=0.05, format="%.2f", label_visibility="collapsed", key=f"visceral_{latest_record_key}")

            muscle_label, muscle_input = st.columns([1, 2])
            with muscle_label:
                st.markdown("<div style='height: 48px; display: flex; align-items: center; font-weight: 700'>筋肉量 (kg)</div>", unsafe_allow_html=True)
            with muscle_input:
                m = st.number_input("筋肉量 (kg)", value=latest_measurement("muscle", 50.0), step=0.05, format="%.2f", label_visibility="collapsed", key=f"muscle_{latest_record_key}")

            water_label, water_input = st.columns([1, 2])
            with water_label:
                st.markdown("<div style='height: 48px; display: flex; align-items: center; font-weight: 700'>体内水分率 (%)</div>", unsafe_allow_html=True)
            with water_input:
                wat = st.number_input("体内水分率 (%)", value=latest_measurement("water", 55.0), step=0.05, format="%.2f", label_visibility="collapsed", key=f"water_{latest_record_key}")
            
            if st.form_submit_button("保存"):
                new_data = {"date": str(d), "weight": w, "bmi": b, "fat_pct": f, "visceral": v, "muscle": m, "water": wat}
                user_info["data"] = [r for r in user_info["data"] if r["date"] != str(d)] + [new_data]
                user_info["data"].sort(key=lambda x: x["date"], reverse=True)
                st.session_state.user = user_info
                
                st.query_params["health_data"] = encode_data(
                    build_save_payload(user_info)
                )
                st.rerun()

    with col2:
        st.subheader("履歴データ")
        backup_header = f"#BACKUP:{encode_data(build_save_payload(user_info))}\n"
        backup_csv = backup_header + pd.DataFrame(user_info["data"]).to_csv(index=False)

        st.download_button(
            label="📥 バックアップファイル(CSV)を保存する",
            data=backup_csv.encode("utf-8-sig"),
            file_name=f"health_data_backup_{datetime.now().strftime('%Y%m%d')}.csv",
            mime="text/csv",
            key="backup_download_btn",
            use_container_width=True,
        )

        uploaded_backup = st.file_uploader(
            "バックアップCSVファイルを読み込む",
            type=["csv"],
            key="history_backup_uploader",
        )

        if uploaded_backup is None:
            st.session_state.pop("history_backup_signature", None)
        else:
            backup_bytes = uploaded_backup.getvalue()
            backup_signature = hashlib.sha256(backup_bytes).hexdigest()
            if st.session_state.get("history_backup_signature") != backup_signature:
                st.session_state["history_backup_signature"] = backup_signature
                try:
                    restored = parse_backup_csv(uploaded_backup)
                    if restored is None or "records" not in restored:
                        raise ValueError("CSVに有効な #BACKUP データがありません。")
                    user_info["data"] = normalize_records(restored["records"])
                    st.session_state.user = user_info
                    st.query_params["health_data"] = encode_data(
                        build_save_payload(user_info)
                    )
                    st.rerun()
                except (OSError, TypeError, ValueError) as exc:
                    st.error(f"バックアップを読み込めません: {exc}")

        if user_info["data"]:
            history_df = pd.DataFrame(user_info["data"])
            history_df = history_df.sort_values("date", ascending=False).reset_index(drop=True)

            display_cols = ["date", "weight", "bmi", "fat_pct", "visceral", "muscle", "water"]
            existing_cols = [c for c in display_cols if c in history_df.columns]
            display_df = history_df[existing_cols].copy()
            
            display_df = display_df.rename(columns={
                "date": "日付", "weight": "体重(kg)", "bmi": "BMI", 
                "fat_pct": "体脂肪率(%)", "visceral": "内臓脂肪", 
                "muscle": "筋肉量(kg)", "water": "体内水分率(%)"
            })

            display_df = display_df.reindex(columns=[
                "日付", "体重(kg)", "BMI", "体脂肪率(%)",
                "内臓脂肪", "筋肉量(kg)", "体内水分率(%)",
            ])
            display_df["日付"] = pd.to_datetime(display_df["日付"], errors="coerce").dt.date
            for col in display_df.columns:
                if col != "日付":
                    display_df[col] = pd.to_numeric(display_df[col], errors="coerce")
            
            st.dataframe(
                display_df,
                width="stretch",
                height=380,
                hide_index=True,
                column_config={
                    "日付": st.column_config.DateColumn("日付", width=95, format="YYYY-MM-DD"),
                    "体重(kg)": st.column_config.NumberColumn("体重(kg)", width=85, format="%.1f"),
                    "BMI": st.column_config.NumberColumn("BMI", width=70, format="%.2f"),
                    "体脂肪率(%)": st.column_config.NumberColumn("体脂肪率(%)", width=105, format="%.1f"),
                    "内臓脂肪": st.column_config.NumberColumn("内臓脂肪", width=85, format="%.1f"),
                    "筋肉量(kg)": st.column_config.NumberColumn("筋肉量(kg)", width=95, format="%.1f"),
                    "体内水分率(%)": st.column_config.NumberColumn("体内水分率(%)", width=110, format="%.1f"),
                },
            )
        else:
            st.info("データがありません。")

    st.write("---")
    
    # 分析ダッシュボード
    st.subheader("📊 分析ダッシュボード")
    if user_info["data"]:
        df = pd.DataFrame(user_info["data"]).sort_values("date")
        df["date"] = pd.to_datetime(df["date"])
        
        if "fat_pct" in df.columns:
            df["fat"] = df["fat_pct"]

        def build_hover_template(label, unit):
            return (
                "<b>%{x|%Y-%m-%d}</b><br>" +
                f"{label}: %{{y:.2f}} {unit}<extra></extra>"
            )

        # 一段目グラフ：体重・筋肉量・体内水分率
        fig1 = go.Figure()
        for name, key, color in [
            ("体重 (kg)", "weight", "#1f77b4"),
            ("筋肉量 (kg)", "muscle", "#2ca02c"),
            ("体内水分率 (%)", "water", "#17becf"),
        ]:
            y_values = numeric_series(df, key)
            fig1.add_trace(
                go.Scatter(
                    x=df["date"],
                    y=y_values,
                    mode="lines+markers",
                    name=name,
                    line=dict(color=color, width=3),
                    marker=dict(size=10, color=color),
                    hovertemplate=build_hover_template(name, ""),
                )
            )

        fig1.update_layout(
            title=dict(
                text="体重・筋肉量・体内水分率の推移",
                pad=dict(b=24),
            ),
            xaxis_title="日付",
            yaxis_title="値",
            template="plotly_white",
            hovermode="closest",
            hoverlabel=dict(font_size=16, font_family="Yu Gothic, Meiryo, sans-serif"),
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="left", x=0),
            margin=dict(l=30, r=20, t=90, b=20),
            height=420,
        )
        fig1.update_xaxes(tickformat="%m月%d日")
        st.plotly_chart(fig1, width="stretch")

        # 二段目グラフ：BMI・体脂肪・内臓脂肪
        fig2 = go.Figure()
        for name, key, color in [
            ("BMI", "bmi", "#ff7f0e"),
            ("体脂肪率 (%)", "fat", "#d62728"),
            ("内臓脂肪レベル", "visceral", "#9467bd"),
        ]:
            y_values = numeric_series(df, key)
            fig2.add_trace(
                go.Scatter(
                    x=df["date"],
                    y=y_values,
                    mode="lines+markers",
                    name=name,
                    line=dict(color=color, width=3),
                    marker=dict(size=10, color=color),
                    hovertemplate=build_hover_template(name, ""),
                )
            )

        fig2.update_layout(
            title=dict(
                text="BMI・体脂肪・内臓脂肪の推移",
                pad=dict(b=24),
            ),
            xaxis_title="日付",
            yaxis_title="値",
            template="plotly_white",
            hovermode="closest",
            hoverlabel=dict(font_size=16, font_family="Yu Gothic, Meiryo, sans-serif"),
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="left", x=0),
            margin=dict(l=30, r=20, t=90, b=20),
            height=420,
        )
        fig2.update_xaxes(tickformat="%m月%d日")
        st.plotly_chart(fig2, width="stretch")
