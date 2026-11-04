import base64
import binascii
import hashlib
import hmac
import html
import json
import math
import os
import re
import secrets
import sqlite3
from collections.abc import Mapping
from datetime import datetime
from io import StringIO
from pathlib import Path
from urllib.parse import urlparse

import httpx
import pandas as pd
import plotly.graph_objects as go
import streamlit as st
from dotenv import load_dotenv
from postgrest.exceptions import APIError
from supabase import create_client, Client, SupabaseException
from streamlit.errors import StreamlitSecretNotFoundError

load_dotenv(dotenv_path=Path(__file__).resolve().parent / ".env")

# ==========================================
# 1. ユーティリティ・データ処理関数
# ==========================================

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


def has_legacy_account(username):
    response = (
        supabase.table("health_accounts")
        .select("username")
        .eq("username", username)
        .limit(1)
        .execute()
    )
    return bool(response.data)


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
    stored_records = response.data[0]["records_json"]
    if isinstance(stored_records, str):
        stored_records = json.loads(stored_records)
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
    if (
        not isinstance(username, str)
        or not username
        or not isinstance(password, str)
        or not isinstance(user_db, dict)
    ):
        return False

    account = user_db.get(username, {})
    if not isinstance(account, dict):
        return False
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


def build_backup_csv(records):
    normalized_records = normalize_records(records)
    csv_buffer = StringIO(newline="")
    csv_buffer.write(f"#BACKUP:{encode_data({'records': normalized_records})}\n")
    if normalized_records:
        pd.DataFrame(normalized_records).to_csv(
            csv_buffer,
            index=False,
            lineterminator="\n",
        )
    else:
        csv_buffer.write("date,weight,bmi,fat_pct,visceral,muscle,water,notes\n")
    return csv_buffer.getvalue().encode("utf-8-sig")


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

if "health_data" in st.query_params:
    del st.query_params["health_data"]


def normalized_mapping(mapping):
    if not isinstance(mapping, Mapping):
        return {}
    return {
        str(key).strip().casefold(): value
        for key, value in mapping.items()
    }


def first_non_empty_string(*values):
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


try:
    flat_secrets = normalized_mapping(st.secrets)
except StreamlitSecretNotFoundError:
    flat_secrets = {}

nested_supabase_secrets = normalized_mapping(flat_secrets.get("supabase", {}))
environment = normalized_mapping(os.environ)

SUPABASE_URL = first_non_empty_string(
    nested_supabase_secrets.get("url"),
    nested_supabase_secrets.get("supabase_url"),
    flat_secrets.get("supabase_url"),
    flat_secrets.get("url"),
    environment.get("supabase_url"),
    environment.get("url"),
)
SUPABASE_KEY = first_non_empty_string(
    nested_supabase_secrets.get("service_role_key"),
    nested_supabase_secrets.get("supabase_service_role_key"),
    nested_supabase_secrets.get("supabase_key"),
    nested_supabase_secrets.get("key"),
    flat_secrets.get("supabase_service_role_key"),
    flat_secrets.get("supabase_key"),
    flat_secrets.get("service_role_key"),
    flat_secrets.get("key"),
    environment.get("supabase_service_role_key"),
    environment.get("supabase_key"),
    environment.get("service_role_key"),
    environment.get("key"),
)

if not SUPABASE_URL or not SUPABASE_KEY:
    st.error("Supabaseの環境変数が設定されていません。")
    st.stop()

supabase = None
SUPABASE_CONFIG_ERROR = ""
if SUPABASE_KEY.startswith("sb_publishable_"):
    SUPABASE_CONFIG_ERROR = (
        "publishable キーではDB操作できません。サーバー側に Supabase の "
        "service_role キーを設定してください。"
    )
else:
    supabase_url_parts = urlparse(SUPABASE_URL)
    if (
        supabase_url_parts.scheme not in ("http", "https")
        or not supabase_url_parts.netloc
    ):
        SUPABASE_CONFIG_ERROR = (
            "SUPABASE_URL は http:// または https:// から始まる有効なURLにしてください。"
        )
    elif supabase_url_parts.hostname == "supabase.co":
        SUPABASE_CONFIG_ERROR = (
            "SUPABASE_URL がプロジェクト固有のURLではありません。"
            "SupabaseのProject URL（例: https://<project-ref>.supabase.co）を設定してください。"
        )
    else:
        try:
            supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
        except (ValueError, SupabaseException, httpx.HTTPError) as exc:
            SUPABASE_CONFIG_ERROR = f"Supabaseクライアントを初期化できません: {exc}"

if SUPABASE_CONFIG_ERROR:
    st.warning(SUPABASE_CONFIG_ERROR)

supabase_available = supabase is not None

if "user" not in st.session_state:
    st.session_state.user = {}

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
            login_submitted = st.form_submit_button(
                "サインイン",
                disabled=not supabase_available,
            )
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
            registration_submitted = st.form_submit_button(
                "登録する",
                disabled=not supabase_available,
            )

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
                registration_succeeded = False
                try:
                    if has_legacy_account(new_username):
                        st.error(
                            "このユーザー名は旧形式のアカウントで使用されています。"
                            "管理者に認証情報の移行を依頼してください。"
                        )
                    else:
                        register_persistent_account(new_username, password_record)
                        persisted_password = load_persistent_password(new_username)
                        if persisted_password is None or any(
                            persisted_password.get(key) != password_record[key]
                            for key in (
                                "password_salt",
                                "password_hash",
                                "password_iterations",
                            )
                        ):
                            raise ValueError(
                                "登録したパスワードを Supabase で確認できません。"
                            )
                        registration_succeeded = True
                except APIError as exc:
                    if getattr(exc, "code", None) == "23505":
                        st.error("このユーザー名はすでに使用されています。")
                    else:
                        st.error(f"Supabaseへアカウントを保存できません: {exc}")
                except (SupabaseException, httpx.HTTPError) as exc:
                    st.error(f"Supabaseへアカウントを保存できません: {exc}")
                except (KeyError, TypeError, ValueError) as exc:
                    st.error(f"アカウントの保存を確認できません: {exc}")
                if registration_succeeded:
                    st.session_state.user = {
                        "username": new_username,
                        "data": [],
                        "user_db": {new_username: persisted_password},
                    }
                    st.rerun()
else:
    user_info = st.session_state.user
    try:
        user_info["data"] = normalize_records(user_info.get("data", []))
        user_info["user_db"] = normalize_user_db(user_info.get("user_db"))
    except (TypeError, ValueError) as exc:
        st.error(f"保存データに不整合があります: {exc}")
        st.session_state.user = {}
        st.rerun()
        st.rerun()
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
        history_heading_col, save_col, export_col, upload_col = st.columns(
            [1.3, 1, 1.35, 1],
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
                disabled=not supabase_available,
            )
        with export_col:
            st.download_button(
                "CSVダウンロード",
                data=build_backup_csv(user_info["data"]),
                file_name=f"bodymetrics_backup_{datetime.now().strftime('%Y%m%d')}.csv",
                mime="text/csv",
                key="download_health_records",
                use_container_width=True,
            )
        with upload_col:
            read_clicked = st.button(
                "読み込み",
                key="show_history_backup_uploader",
                use_container_width=True,
                disabled=not supabase_available,
            )
            if read_clicked:
                st.session_state.show_history_backup_uploader = True
                st.session_state.history_backup_upload_version = (
                    st.session_state.get("history_backup_upload_version", 0) + 1
                )
                st.session_state.pop("history_backup_signature", None)

        uploaded_backup = None
        if (
            supabase_available
            and st.session_state.get("show_history_backup_uploader", False)
        ):
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
            record_saved = False
            try:
                save_persistent_records(user_info["username"], updated_records)
            except (APIError, SupabaseException, httpx.HTTPError) as exc:
                st.error(f"Supabaseへ健康記録を保存できません: {exc}")
            except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
                st.error(f"健康記録を永続保存できません: {exc}")
            else:
                record_saved = True
            if record_saved:
                user_info["data"] = updated_records
                st.session_state.user = user_info
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
```
