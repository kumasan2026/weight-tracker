import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import json
import base64
import binascii
import html
import hashlib
import hmac
import math
import os
import re
import secrets
import os
import json
import base64
import binascii
import sqlite3
import httpx
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

# --- ここからクラウド（Supabase）に繋ぐための新しい設定 ---
from dotenv import load_dotenv
from postgrest.exceptions import APIError
from supabase import create_client, Client, SupabaseException

load_dotenv()

SUPABASE_URL = "https://tmcpcssxsdbehduhhfvz.supabase.co"
SUPABASE_KEY = "sb_publishable_TPJL-EFIFxof5cjuQurivA_Qi6rSGmE"
# --- ここまで ---

# ==========================================
# 1. ユーティリティ・データ処理関数
# ==========================================

PASSWORD_HASH_ITERATIONS = 310_000

# In production, point BODYMETRICS_AUTH_DB at a writable persistent volume.


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


def initialize_password_store():
    # Supabaseではブラウザ画面でテーブルを作成するため、プログラム側での初期化は不要です
    pass


def load_persistent_password(username):
    response = (
        supabase.table("auth_credentials")
        .select("password_salt, password_hash, password_iterations")
        .eq("username", username)
        .limit(1)
        .execute()
    )
    if not response.data:
        return None
    row = response.data[0]
    return {
        "password_salt": row["password_salt"],
        "password_hash": row["password_hash"],
        "password_iterations": row["password_iterations"],
    }


def save_persistent_password(username, password_record):
    supabase.table("auth_credentials").upsert(
        {
            "username": username,
            "password_salt": password_record["password_salt"],
            "password_hash": password_record["password_hash"],
            "password_iterations": password_record["password_iterations"],
            "updated_at": datetime.now().astimezone().isoformat(),
        },
        on_conflict="username",
    ).execute()


def register_persistent_account(username, password_record):
    supabase.table("auth_credentials").insert({
        "username": username,
        "password_salt": password_record["password_salt"],
        "password_hash": password_record["password_hash"],
        "password_iterations": password_record["password_iterations"],
        "updated_at": datetime.now().astimezone().isoformat()
    }).execute()


def load_persistent_records(username):
    response = (
        supabase.table("health_records")
        .select("records_json")
        .eq("username", username)
        .limit(1)
        .execute()
    )
    if not response.data:
        return []
    stored_records = json.loads(response.data[0]["records_json"])
    return normalize_records(stored_records)


def save_persistent_records(username, records):
    normalized_records = normalize_records(records)
    records_json = json.dumps(
        normalized_records,
        ensure_ascii=False,
        allow_nan=False,
    )
    supabase.table("health_records").upsert({
        "username": username,
        "records_json": records_json,
        "updated_at": datetime.now().astimezone().isoformat()
    }).execute()




def verify_login(username, password, user_db):
    if not isinstance(username, str) or not username:
        return False

    account = user_db.get(username, {})
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

    normalized_user_db = dict(user_db)
    for username, account in user_db.items():
        if not isinstance(username, str) or not isinstance(account, dict):
            raise ValueError("ユーザー設定データの形式が正しくありません。")
        normalized_account = dict(account)
        normalized_account.pop("password", None)
        normalized_user_db[username] = normalized_account
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

st.set_page_config(page_title="BodyMetrics", layout="wide")

if (
    not SUPABASE_URL.strip()
    or not SUPABASE_KEY.strip()
    or SUPABASE_URL == "あなたのSupabaseのURL"
    or SUPABASE_KEY == "あなたのSupabaseのKEY"
):
    st.error(
        "Supabaseの接続情報が未設定です。app.py の SUPABASE_URL / "
        "SUPABASE_KEY に実際の値を設定するか、同名の環境変数を設定してください。"
    )
    st.stop()

supabase_url_parts = urlparse(SUPABASE_URL)
if supabase_url_parts.scheme not in ("http", "https") or not supabase_url_parts.netloc:
    st.error("SUPABASE_URL は http:// または https:// から始まる有効なURLにしてください。")
    st.stop()

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

try:
    initialize_password_store()
except (OSError, sqlite3.Error) as exc:
    st.error(f"パスワード保存領域を初期化できません: {exc}")
    st.stop()

if "user" not in st.session_state:
    st.session_state.user = {}

if not st.session_state.user:
    encoded_data = st.query_params.get("health_data")
    if encoded_data:
        try:
            restored_payload = decode_data(encoded_data)
            if "user_db" not in restored_payload or "records" not in restored_payload:
                raise ValueError("ログイン情報の形式が正しくありません。")

            restored_user_db = normalize_user_db(restored_payload["user_db"])
            if len(restored_user_db) != 1:
                raise ValueError("URLからログインするユーザーを特定できません。")

            restored_username = next(iter(restored_user_db))
            if not restored_username:
                raise ValueError("ユーザー名がありません。")

            restored_account = restored_user_db[restored_username]
            persistent_password = load_persistent_password(restored_username)
            password_fields = (
                "password_salt",
                "password_hash",
                "password_iterations",
            )
            if persistent_password is None or any(
                restored_account.get(key) != persistent_password[key]
                for key in password_fields
            ):
                raise ValueError("ログイン情報が最新ではありません。再度サインインしてください。")

            st.session_state.user = {
                "username": restored_username,
                "data": normalize_records(restored_payload["records"]),
                "user_db": restored_user_db,
            }
        except (APIError, SupabaseException, httpx.HTTPError) as exc:
            st.error(f"Supabaseのパスワードを確認できません: {exc}")
        except sqlite3.Error as exc:
            st.error(f"保存済みパスワードを確認できません: {exc}")
        except (TypeError, ValueError) as exc:
            st.error(f"URLのログイン情報を復元できません: {exc}")

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
        white-space: nowrap !important;
        word-break: keep-all !important;
    }

    h1 {
        white-space: nowrap !important;
        word-break: keep-all !important;
        font-size: clamp(1.7rem, 2.4vw, 2.5rem) !important;
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
        word-break: keep-all !important;
    }

    .st-key-save_daily_record button {
        font-size: 0.75rem !important;
        padding: 5px 6px !important;
    }

    .st-key-history_heading h2,
    .st-key-history_heading h3 {
        font-size: 1.15rem !important;
        white-space: nowrap !important;
        word-break: keep-all !important;
    }

    .st-key-save_daily_record,
    .st-key-history_backup_uploader,
    .st-key-history_heading {
        min-width: 0 !important;
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

    /* CSV読み込み上限の補助表示だけを隠す */
    .st-key-history_backup_uploader [data-testid="stFileUploaderDropzone"] small {
        display: none !important;
    }

    .user-header-name {
        display: flex;
        align-items: center;
        justify-content: flex-end;
        min-height: 3.3rem;
        font-size: 1.05rem;
        font-weight: 700;
        white-space: nowrap;
    }

    .st-key-logout_button {
        padding-top: 0.35rem;
    }

    .st-key-logout_button button {
        min-height: 44px;
    }
    </style>
""", unsafe_allow_html=True)

# 新規サインイン用の初期データ。共有された最新JSONのrecordsをここに設定します。
initial_records = []

is_logged_in = "username" in st.session_state.user

if is_logged_in:
    title_col, header_name_col, header_logout_col, _ = st.columns(
        [3.3, 1.7, 1.7, 3.3],
        vertical_alignment="center",
    )
    with title_col:
        st.title("📊 BodyMetrics")
    with header_name_col:
        st.markdown(
            '<div class="user-header-name">👤 '
            f'{html.escape(st.session_state.user["username"])}</div>',
            unsafe_allow_html=True,
        )
    with header_logout_col:
        logout_clicked = st.button(
            "ログアウト",
            key="logout_button",
            use_container_width=True,
        )
    if logout_clicked:
        st.session_state.user = {}
        if "health_data" in st.query_params:
            del st.query_params["health_data"]
        st.rerun()
else:
    st.title("📊 BodyMetrics")

if not is_logged_in:
    def sign_in(username, password):
        username = username.strip()
        try:
            persistent_password = load_persistent_password(username)
        except (APIError, SupabaseException, httpx.HTTPError) as exc:
            st.error(f"Supabaseのパスワードを読み込めません: {exc}")
            return
        except sqlite3.Error as exc:
            st.error(f"保存済みパスワードを読み込めません: {exc}")
            return

        if persistent_password is None:
            st.error("ユーザー名またはパスワードが正しくありません。")
            return

        account = dict(persistent_password)
        login_user_db = {username: account}

        if not verify_login(username, password, login_user_db):
            st.error("ユーザー名またはパスワードが正しくありません。")
            return

        try:
            records = load_persistent_records(username)
        except ValueError as exc:
            st.error(f"記録データを読み込めません: {exc}")
            return
        except (APIError, SupabaseException, httpx.HTTPError, json.JSONDecodeError) as exc:
            st.error(f"Supabaseから健康記録を読み込めません: {exc}")
            return
        except sqlite3.Error as exc:
            st.error(f"保存済みの健康記録を読み込めません: {exc}")
            return

        st.session_state.user = {
            "username": username,
            "data": records,
            "user_db": {username: account},
        }
        st.query_params["health_data"] = encode_data(
            build_save_payload(st.session_state.user)
        )
        st.rerun()

    st.subheader("ログイン / アカウント作成")
    st.caption("健康記録はアカウントごとに自動保存され、ログイン時に読み込まれます。")
    login_tab, register_tab = st.tabs(["通常ログイン", "新規アカウント登録"])

    with login_tab:
        with st.form("login_form"):
            user_input = st.text_input("ユーザー名", value="tomato", key="login_username")
            pass_input = st.text_input(
                "パスワード",
                type="password",
                key="login_password",
            )
            login_submitted = st.form_submit_button("サインイン")
        if login_submitted:
            sign_in(user_input, pass_input)

    with register_tab:
        with st.form("register_form"):
            new_username = st.text_input(
                "希望のユーザー名",
                key="register_username",
            )
            new_password = st.text_input(
                "パスワード",
                type="password",
                key="register_password",
            )
            confirm_password = st.text_input(
                "パスワード（確認）",
                type="password",
                key="register_password_confirm",
            )
            registration_submitted = st.form_submit_button("登録する")

        if registration_submitted:
            new_username = new_username.strip()
            if not re.fullmatch(r"[\w.-]{3,32}", new_username, flags=re.UNICODE):
                st.error("ユーザー名は3〜32文字で入力してください（文字・数字・._- が使用できます）。")
            elif new_username == "tomato":
                st.error("このユーザー名はすでに使用されています。")
            elif len(new_password) < 8:
                st.error("パスワードは8文字以上で入力してください。")
            elif new_password != confirm_password:
                st.error("パスワードが一致しません。")
            else:
                password_record = create_password_hash(new_password)
                try:
                    register_persistent_account(new_username, password_record)
                except sqlite3.IntegrityError:
                    st.error("このユーザー名はすでに使用されています。")
                except (OSError, sqlite3.Error) as exc:
                    st.error(f"アカウントを保存できません: {exc}")
                else:
                    st.session_state.user = {
                        "username": new_username,
                        "data": [],
                        "user_db": {new_username: password_record},
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
                    "notes",
                )
            ],
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()[:12]

    def latest_measurement(column, default):
        value = latest_record.get(column)
        return default if value is None else value

    with st.sidebar.form("password_change_form", clear_on_submit=True):
        new_password = st.text_input(
            "新しいパスワード",
            type="password",
            key="new_password_input",
        )
        confirm_password = st.text_input(
            "新しいパスワード（確認）",
            type="password",
            key="confirm_password_input",
        )
        if st.form_submit_button("パスワードを更新する"):
            if not new_password:
                st.error("新しいパスワードを入力してください。")
            elif new_password != confirm_password:
                st.error("新しいパスワードが一致しません。")
            else:
                username = user_info["username"]
                password_record = create_password_hash(new_password)
                try:
                    save_persistent_password(username, password_record)
                    persisted_password = load_persistent_password(username)
                    if (
                        persisted_password is None
                        or not hmac.compare_digest(
                            persisted_password["password_salt"],
                            password_record["password_salt"],
                        )
                        or not hmac.compare_digest(
                            persisted_password["password_hash"],
                            password_record["password_hash"],
                        )
                        or persisted_password["password_iterations"]
                        != password_record["password_iterations"]
                    ):
                        raise ValueError("保存後のパスワード情報を確認できません。")
                except (APIError, SupabaseException, httpx.HTTPError) as exc:
                    st.sidebar.error(f"Supabaseへパスワードを保存できません: {exc}")
                except (OSError, sqlite3.Error) as exc:
                    st.sidebar.error(f"パスワードを永続保存できません: {exc}")
                except (KeyError, TypeError, ValueError) as exc:
                    st.sidebar.error(f"パスワード更新を確認できません: {exc}")
                else:
                    user_info["user_db"][username] = dict(persisted_password)
                    st.session_state.user = user_info
                    st.query_params["health_data"] = encode_data(
                        build_save_payload(user_info)
                    )
                    st.session_state.password_change_success = True
                    st.rerun()

    if st.session_state.pop("password_change_success", False):
        st.sidebar.success("パスワードを更新しました。")

    col1, col2 = st.columns([1.8, 3.2])
    
    with col1:
        st.subheader("本日の記録")
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

        note_label, note_input = st.columns([1, 2])
        with note_label:
            st.markdown("<div style='height: 48px; display: flex; align-items: center; font-weight: 700'>メモ</div>", unsafe_allow_html=True)
        with note_input:
            n = st.text_area("メモ", value=latest_measurement("notes", ""), placeholder="今日の体調やメモを自由に入力できます", label_visibility="collapsed", key=f"notes_{latest_record_key}")
    
    with col2:
        history_heading_col, save_col, upload_col = st.columns(
            [1.3, 1, 1],
            gap="small",
            vertical_alignment="center",
        )
        with history_heading_col:
            with st.container(key="history_heading"):
                st.subheader("履歴データ")
        with save_col:
            save_clicked = st.button(
                "保存",
                key="save_daily_record",
                use_container_width=True,
            )
        with upload_col:
            read_clicked = st.button(
                "読み込み",
                key="show_history_backup_uploader",
                use_container_width=True,
            )
            if read_clicked:
                st.session_state.show_history_backup_uploader = True
                st.session_state.history_backup_upload_version = (
                    st.session_state.get("history_backup_upload_version", 0) + 1
                )
                st.session_state.pop("history_backup_signature", None)

        uploaded_backup = None
        if st.session_state.get("show_history_backup_uploader", False):
            upload_version = st.session_state.get("history_backup_upload_version", 0)
            with st.container(key="history_backup_uploader"):
                uploaded_backup = st.file_uploader(
                    "CSVファイルを選択",
                    type=["csv"],
                    key=f"history_backup_file_{upload_version}",
                    label_visibility="collapsed",
                )

        if save_clicked:
            new_data = {
                "date": str(d),
                "weight": w,
                "bmi": b,
                "fat_pct": f,
                "visceral": v,
                "muscle": m,
                "water": wat,
                "notes": n,
            }
            updated_records = [
                record
                for record in user_info["data"]
                if record["date"] != str(d)
            ] + [new_data]
            updated_records.sort(key=lambda record: record["date"], reverse=True)
            try:
                save_persistent_records(user_info["username"], updated_records)
            except (APIError, SupabaseException, httpx.HTTPError) as exc:
                st.error(f"Supabaseへ健康記録を保存できません: {exc}")
                st.stop()
            except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
                st.error(f"健康記録を永続保存できません: {exc}")
                st.stop()
            user_info["data"] = updated_records
            st.session_state.user = user_info
            st.query_params["health_data"] = encode_data(
                build_save_payload(user_info)
            )
            st.rerun()

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
                    restored_records = normalize_records(restored["records"])
                    save_persistent_records(user_info["username"], restored_records)
                    user_info["data"] = restored_records
                    st.session_state.user = user_info
                    st.session_state.show_history_backup_uploader = False
                    st.session_state.history_backup_upload_version = (
                        st.session_state.get("history_backup_upload_version", 0) + 1
                    )
                    st.session_state.pop("history_backup_signature", None)
                    st.query_params["health_data"] = encode_data(
                        build_save_payload(user_info)
                    )
                    st.rerun()
                except (APIError, SupabaseException, httpx.HTTPError) as exc:
                    st.error(f"Supabaseへバックアップを保存できません: {exc}")
                except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
                    st.error(f"バックアップを読み込めません: {exc}")

        if user_info["data"]:
            history_df = pd.DataFrame(user_info["data"])
            history_df = history_df.sort_values("date", ascending=False).reset_index(drop=True)

            display_cols = ["date", "weight", "bmi", "fat_pct", "visceral", "muscle", "water", "notes"]
            for column in display_cols:
                if column not in history_df.columns:
                    history_df[column] = "" if column == "notes" else None
            display_df = history_df[display_cols].copy()
            
            display_df = display_df.rename(columns={
                "date": "日付", "weight": "体重(kg)", "bmi": "BMI", 
                "fat_pct": "体脂肪率(%)", "visceral": "内臓脂肪", 
                "muscle": "筋肉量(kg)", "water": "体内水分率(%)",
                "notes": "メモ",
            })

            display_df = display_df.reindex(columns=[
                "日付", "体重(kg)", "BMI", "体脂肪率(%)",
                "内臓脂肪", "筋肉量(kg)", "体内水分率(%)", "メモ",
            ])
            display_df["日付"] = pd.to_datetime(display_df["日付"], errors="coerce").dt.date
            for col in display_df.columns:
                if col not in ("日付", "メモ"):
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
                    "メモ": st.column_config.TextColumn("メモ", width=250),
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
