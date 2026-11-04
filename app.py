import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import json
import base64
import binascii
import hashlib
import hmac
import math
import os
import re
import httpx
import psycopg
from collections.abc import Mapping
from pathlib import Path
from streamlit.errors import StreamlitSecretNotFoundError
from datetime import datetime

# ==========================================
# 1. ユーティリティ・データ処理関数
# ==========================================

SUPABASE_TIMEOUT_SECONDS = 15
SUPABASE_SCHEMA_VERSION = 2
PASSWORD_HASH_ITERATIONS = 600_000
PASSWORD_MIN_LENGTH = 12
RECORD_COLUMNS = (
    "date",
    "weight",
    "bmi",
    "fat_pct",
    "visceral",
    "muscle",
    "water",
)


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


class SupabaseError(Exception):
    def __init__(self, status_code, message):
        self.status_code = status_code
        super().__init__(message)


class SupabaseConflictError(SupabaseError):
    pass


def get_supabase_config():
    try:
        secrets_config = st.secrets
        # supabaseグループがあっても無くても、全体から探せるように修正
        supabase_secrets = secrets_config.get("supabase") if secrets_config.get("supabase") else secrets_config

    except StreamlitSecretNotFoundError:
        secrets_config = {}
        supabase_secrets = {}

    if not isinstance(supabase_secrets, Mapping):
        raise RuntimeError("Streamlit secrets の [supabase] は設定形式が正しくありません。")

    supabase_url = (
        os.environ.get("SUPABASE_URL")
        or secrets_config.get("SUPABASE_URL")
        or supabase_secrets.get("url")
    )
    service_role_key = (
        os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
        or secrets_config.get("SUPABASE_SERVICE_ROLE_KEY")
        or supabase_secrets.get("service_role_key")
    )
    if not supabase_url or not service_role_key:
        raise RuntimeError(
            "SUPABASE_URL と SUPABASE_SERVICE_ROLE_KEY を環境変数、"
            "または Streamlit secrets の [supabase] に設定してください。"
        )
    return str(supabase_url).rstrip("/"), str(service_role_key)


def get_supabase_database_url():
    try:
        secrets_config = st.secrets
        supabase_secrets = secrets_config.get("supabase", {})
    except StreamlitSecretNotFoundError:
        secrets_config = {}
        supabase_secrets = {}

    database_url = (
        os.environ.get("SUPABASE_DB_URL")
        or secrets_config.get("SUPABASE_DB_URL")
        or supabase_secrets.get("db_url")
    )
    if not database_url:
        raise RuntimeError(
            "初回テーブル作成には Supabase の PostgreSQL 接続URLが必要です。"
        )
    return str(database_url)


def get_shared_login_password():
    try:
        password = st.secrets.get("PASSWORD")
    except StreamlitSecretNotFoundError as exc:
        raise RuntimeError(
            "Streamlit secrets に PASSWORD を設定してください。"
        ) from exc
    if not isinstance(password, str) or not password:
        raise RuntimeError(
            "Streamlit secrets に PASSWORD = \"...\" を設定してください。"
        )
    return password


def hash_password(password):
    salt = os.urandom(16)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PASSWORD_HASH_ITERATIONS,
    )
    salt_text = base64.urlsafe_b64encode(salt).decode("ascii").rstrip("=")
    hash_text = base64.urlsafe_b64encode(password_hash).decode("ascii").rstrip("=")
    return f"pbkdf2_sha256${PASSWORD_HASH_ITERATIONS}${salt_text}${hash_text}"


def verify_password(password, encoded_hash):
    try:
        algorithm, iterations_text, salt_text, expected_hash_text = encoded_hash.split("$")
        iterations = int(iterations_text)
        if algorithm != "pbkdf2_sha256" or not 100_000 <= iterations <= 2_000_000:
            raise ValueError
        salt = base64.urlsafe_b64decode(salt_text + "=" * (-len(salt_text) % 4))
        expected_hash = base64.urlsafe_b64decode(
            expected_hash_text + "=" * (-len(expected_hash_text) % 4)
        )
        if len(salt) != 16 or len(expected_hash) != 32:
            raise ValueError
    except (AttributeError, TypeError, ValueError, binascii.Error) as exc:
        raise ValueError("保存されたアカウントのパスワード情報が正しくありません。") from exc

    actual_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
    )
    return hmac.compare_digest(actual_hash, expected_hash)


def supabase_request(method, table, params=None, payload=None, prefer=None):
    supabase_url, service_role_key = get_supabase_config()
    headers = {
        "apikey": service_role_key,
        "Authorization": f"Bearer {service_role_key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if prefer:
        headers["Prefer"] = prefer

    try:
        response = httpx.request(
            method,
            f"{supabase_url}/rest/v1/{table}",
            params=params,
            json=payload,
            headers=headers,
            timeout=SUPABASE_TIMEOUT_SECONDS,
        )
    except httpx.RequestError as exc:
        raise SupabaseError(None, f"Supabaseに接続できません: {exc}") from exc

    if response.status_code == 409:
        raise SupabaseConflictError(
            response.status_code,
            f"Supabaseで一意制約に競合しました: {response.text}",
        )
    if not response.is_success:
        try:
            error = response.json()
            message = error.get("message") or error.get("details") or response.text
        except (ValueError, AttributeError):
            message = response.text
        raise SupabaseError(
            response.status_code,
            f"Supabase API エラー ({response.status_code}): {message}",
        )
    if not response.content:
        return None
    try:
        return response.json()
    except ValueError as exc:
        raise SupabaseError(
            response.status_code,
            "SupabaseからJSON以外の応答が返されました。",
        ) from exc


@st.cache_resource(show_spinner=False)
def initialize_supabase_schema():
    try:
        versions = supabase_request(
            "GET",
            "app_schema_version",
            params={
                "select": "version",
                "order": "version.desc",
                "limit": "1",
            },
        )
    except SupabaseError as exc:
        if exc.status_code != 404:
            raise
        versions = []

    if versions:
        if (
            not isinstance(versions, list)
            or not isinstance(versions[0], dict)
            or not isinstance(versions[0].get("version"), int)
        ):
            raise RuntimeError("Supabaseのスキーマバージョン情報が正しくありません。")
        if versions[0]["version"] >= SUPABASE_SCHEMA_VERSION:
            return True

    database_url = get_supabase_database_url()
    schema_path = Path(__file__).with_name("supabase_schema.sql")
    try:
        schema_statements = [
            statement.strip()
            for statement in schema_path.read_text(encoding="utf-8").split(";")
            if statement.strip()
        ]
    except OSError as exc:
        raise RuntimeError(
            f"Supabaseスキーマファイルを読み込めません: {exc}"
        ) from exc

    try:
        with psycopg.connect(
            database_url,
            connect_timeout=SUPABASE_TIMEOUT_SECONDS,
            sslmode="require",
        ) as connection:
            with connection.cursor() as cursor:
                for statement in schema_statements:
                    cursor.execute(statement)
    except psycopg.Error as exc:
        raise RuntimeError(
            f"Supabaseの初期テーブル設定に失敗しました: {exc}"
        ) from exc

    versions = supabase_request(
        "GET",
        "app_schema_version",
        params={
            "select": "version",
            "order": "version.desc",
            "limit": "1",
        },
    )
    if (
        not versions
        or not isinstance(versions[0], dict)
        or versions[0].get("version") != SUPABASE_SCHEMA_VERSION
    ):
        raise RuntimeError("Supabaseのスキーマ設定を確認できませんでした。")
    return True


def load_persistent_records(username):
    rows = supabase_request(
        "GET",
        "health_records",
        params={
            "select": "records_json",
            "username": f"eq.{username}",
            "limit": "1",
        },
    )
    if not rows:
        return []
    if not isinstance(rows, list) or not isinstance(rows[0], dict):
        raise SupabaseError(None, "Supabaseの健康記録の形式が正しくありません。")
    return normalize_records(rows[0].get("records_json"))


def load_password_hash(username):
    rows = supabase_request(
        "GET",
        "health_accounts",
        params={
            "select": "password_hash",
            "username": f"eq.{username}",
            "limit": "1",
        },
    )
    if not rows:
        return None
    if (
        not isinstance(rows, list)
        or not isinstance(rows[0], dict)
        or not isinstance(rows[0].get("password_hash"), str)
    ):
        raise SupabaseError(None, "Supabaseのアカウント情報の形式が正しくありません。")
    return rows[0]["password_hash"]


def create_password_account(username, password):
    rows = supabase_request(
        "POST",
        "health_accounts",
        params={"on_conflict": "username", "select": "username"},
        payload={
            "username": username,
            "password_hash": hash_password(password),
            "updated_at": datetime.now().astimezone().isoformat(),
        },
        prefer="resolution=ignore-duplicates,return=representation",
    )
    if not isinstance(rows, list) or len(rows) != 1:
        raise SupabaseConflictError(409, "このユーザー名のアカウントは既に登録されています。")
    return load_password_hash(username)


def save_persistent_records(username, records):
    normalized_records = normalize_records(records)
    persisted_rows = supabase_request(
        "POST",
        "health_records",
        params={"on_conflict": "username", "select": "records_json"},
        payload={
            "username": username,
            "records_json": normalized_records,
            "updated_at": datetime.now().astimezone().isoformat(),
        },
        prefer="resolution=merge-duplicates,return=representation",
    )
    if (
        not isinstance(persisted_rows, list)
        or len(persisted_rows) != 1
        or not isinstance(persisted_rows[0], dict)
    ):
        raise SupabaseError(None, "保存結果をSupabaseから確認できませんでした。")
    persisted_records = normalize_records(persisted_rows[0].get("records_json"))
    if persisted_records != normalized_records:
        raise SupabaseError(None, "Supabaseに保存された健康記録が送信内容と一致しません。")
    return persisted_records


def build_save_payload(user_info):
    return {"records": user_info["data"]}


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

    records_by_date = {}
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

        records_by_date[normalized_record["date"]] = normalized_record
    return [records_by_date[date] for date in sorted(records_by_date)]


def sync_record_input_state(username, records):
    latest_record = max(records, key=lambda record: record["date"], default={})
    signature = hashlib.sha256(
        json.dumps(
            [username, [latest_record.get(column) for column in RECORD_COLUMNS]],
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    if st.session_state.get("record_form_source") == signature:
        return

    defaults = {
        "input_weight": 70.0,
        "input_bmi": 22.0,
        "input_fat_pct": 20.0,
        "input_visceral": 5.0,
        "input_muscle": 50.0,
        "input_water": 55.0,
    }
    for column, key in (
        ("weight", "input_weight"),
        ("bmi", "input_bmi"),
        ("fat_pct", "input_fat_pct"),
        ("visceral", "input_visceral"),
        ("muscle", "input_muscle"),
        ("water", "input_water"),
    ):
        value = latest_record.get(column)
        st.session_state[key] = defaults[key] if value is None else value
    st.session_state.record_form_source = signature


def numeric_series(frame, column):
    if column not in frame.columns:
        return pd.Series(float("nan"), index=frame.index, dtype="float64")
    return pd.to_numeric(frame[column], errors="coerce")


# ==========================================
# 2. メインアプリケーション設定
# ==========================================

st.set_page_config(page_title="BodyMetrics - 統合健康管理システム", layout="wide")
try:
    get_supabase_config()
    initialize_supabase_schema()
    get_shared_login_password()
except (RuntimeError, SupabaseError) as exc:
    st.error(
        f"ログインまたはSupabaseの設定が必要です: {exc} "
        "Supabase の API キーと PostgreSQL 接続URLを確認してください。"
    )
    st.stop()
if "health_data" in st.query_params:
    del st.query_params["health_data"]

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

    /* 履歴CSVアップローダーをコンパクトな横長バーにする */
    .st-key-history_backup_uploader [data-testid="stFileUploader"] {
        padding: 0 !important;
        margin: 0 !important;
    }

    .st-key-history_backup_uploader [data-testid="stFileUploaderDropzone"] {
        box-sizing: border-box !important;
        min-height: 52px !important;
        padding: 6px 12px !important;
        display: flex !important;
        flex-direction: row !important;
        align-items: center !important;
        justify-content: center !important;
        gap: 10px !important;
    }

    .st-key-history_backup_uploader [data-testid="stFileUploaderDropzone"] section,
    .st-key-history_backup_uploader [data-testid="stFileUploaderDropzone"] small {
        display: none !important;
    }

    .st-key-history_backup_uploader [data-testid="stFileUploaderDropzone"] button {
        box-sizing: border-box !important;
        width: 100% !important;
        min-height: 38px !important;
        padding: 8px 12px !important;
        border: 0 !important;
        background: transparent !important;
        box-shadow: none !important;
        color: transparent !important;
        font-size: 0 !important;
        line-height: 0 !important;
    }

    .st-key-history_backup_uploader [data-testid="stFileUploaderDropzone"] button::after {
        content: "📥 過去データを読み込む";
        color: #31333F !important;
        font-size: 14px !important;
        font-weight: 700 !important;
        line-height: 1.2 !important;
        white-space: nowrap !important;
    }
    </style>
""", unsafe_allow_html=True)

if "user" not in st.session_state:
    st.session_state.user = {}

is_logged_in = "username" in st.session_state.user

if not is_logged_in:
    st.subheader("ログイン / アカウント登録")
    auth_mode = st.radio(
        "操作",
        ("ログイン", "新規登録"),
        horizontal=True,
        label_visibility="collapsed",
        key="auth_mode",
    )
    if auth_mode == "ログイン":
        st.caption("登録済みアカウントの固定パスワードでログインしてください。")
        with st.form("login_form"):
            user_input = st.text_input("ユーザー名", key="login_username")
            pass_input = st.text_input(
                "パスワード",
                type="password",
                key="login_password",
            )
            login_submitted = st.form_submit_button("サインイン")
        if login_submitted:
            username = user_input.strip()
            if not re.fullmatch(r"[\w.-]{3,32}", username, flags=re.UNICODE):
                st.error("ユーザー名は3〜32文字で入力してください（文字・数字・._- が使用できます）。")
            else:
                try:
                    password_hash = load_password_hash(username)
                    if password_hash is None or not verify_password(pass_input, password_hash):
                        st.error("ユーザー名またはパスワードが正しくありません。新規登録が必要な場合は「新規登録」を選択してください。")
                    else:
                        records = load_persistent_records(username)
                        st.session_state.user = {
                            "username": username,
                            "data": records,
                        }
                        st.rerun()
                except (RuntimeError, SupabaseError, TypeError, ValueError) as exc:
                    st.error(f"ログインまたは保存済みデータの読み込みに失敗しました: {exc}")
    else:
        st.caption("Secrets の共通パスワードで登録を認可します。登録後の個別パスワードは変更できません。")
        with st.form("registration_form", clear_on_submit=True):
            registration_username = st.text_input("ユーザー名", key="registration_username")
            shared_password_input = st.text_input(
                "共通パスワード（管理者から共有された値）",
                type="password",
                key="registration_shared_password",
            )
            registration_password = st.text_input(
                "個別パスワード（12文字以上）",
                type="password",
                key="registration_password",
            )
            registration_password_confirm = st.text_input(
                "個別パスワード（確認）",
                type="password",
                key="registration_password_confirm",
            )
            registration_submitted = st.form_submit_button("アカウントを作成")
        if registration_submitted:
            username = registration_username.strip()
            if not re.fullmatch(r"[\w.-]{3,32}", username, flags=re.UNICODE):
                st.error("ユーザー名は3〜32文字で入力してください（文字・数字・._- が使用できます）。")
            elif len(registration_password) < PASSWORD_MIN_LENGTH:
                st.error(f"個別パスワードは{PASSWORD_MIN_LENGTH}文字以上にしてください。")
            elif registration_password != registration_password_confirm:
                st.error("個別パスワードと確認用パスワードが一致しません。")
            else:
                try:
                    shared_password = get_shared_login_password()
                    if not hmac.compare_digest(
                        shared_password_input.encode("utf-8"),
                        shared_password.encode("utf-8"),
                    ):
                        st.error("共通パスワードが正しくありません。")
                    elif load_password_hash(username) is not None:
                        st.error("このユーザー名は既に登録されています。ログインしてください。")
                    else:
                        records = load_persistent_records(username)
                        create_password_account(username, registration_password)
                        saved_hash = load_password_hash(username)
                        if saved_hash is None or not verify_password(
                            registration_password,
                            saved_hash,
                        ):
                            raise SupabaseError(
                                None,
                                "アカウント作成後のパスワード検証に失敗しました。",
                            )
                        st.session_state.user = {
                            "username": username,
                            "data": records,
                        }
                        st.rerun()
                except (RuntimeError, SupabaseError, TypeError, ValueError) as exc:
                    st.error(f"アカウントを作成できませんでした: {exc}")
else:
    user_info = st.session_state.user
    try:
        user_info["data"] = normalize_records(user_info.get("data", []))
    except (TypeError, ValueError) as exc:
        st.error(f"保存データに不整合があります: {exc}")
        st.stop()
    st.sidebar.title(f"👤 {user_info['username']}")
    sync_record_input_state(user_info["username"], user_info["data"])

    if st.sidebar.button("サインアウト"):
        st.session_state.user = {}
        st.session_state.pop("record_form_source", None)
        for key in (
            "input_weight",
            "input_bmi",
            "input_fat_pct",
            "input_visceral",
            "input_muscle",
            "input_water",
        ):
            st.session_state.pop(key, None)
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
                w = st.number_input("体重 (kg)", step=0.05, format="%.2f", label_visibility="collapsed", key="input_weight")

            bmi_label, bmi_input = st.columns([1, 2])
            with bmi_label:
                st.markdown("<div style='height: 48px; display: flex; align-items: center; font-weight: 700'>BMI</div>", unsafe_allow_html=True)
            with bmi_input:
                b = st.number_input("BMI", step=0.05, format="%.2f", label_visibility="collapsed", key="input_bmi")

            fat_label, fat_input = st.columns([1, 2])
            with fat_label:
                st.markdown("<div style='height: 48px; display: flex; align-items: center; font-weight: 700'>体脂肪率 (%)</div>", unsafe_allow_html=True)
            with fat_input:
                f = st.number_input("体脂肪率 (%)", step=0.05, format="%.2f", label_visibility="collapsed", key="input_fat_pct")

            visceral_label, visceral_input = st.columns([1, 2])
            with visceral_label:
                st.markdown("<div style='height: 48px; display: flex; align-items: center; font-weight: 700'>内臓脂肪レベル</div>", unsafe_allow_html=True)
            with visceral_input:
                v = st.number_input("内臓脂肪レベル", step=0.05, format="%.2f", label_visibility="collapsed", key="input_visceral")

            muscle_label, muscle_input = st.columns([1, 2])
            with muscle_label:
                st.markdown("<div style='height: 48px; display: flex; align-items: center; font-weight: 700'>筋肉量 (kg)</div>", unsafe_allow_html=True)
            with muscle_input:
                m = st.number_input("筋肉量 (kg)", step=0.05, format="%.2f", label_visibility="collapsed", key="input_muscle")

            water_label, water_input = st.columns([1, 2])
            with water_label:
                st.markdown("<div style='height: 48px; display: flex; align-items: center; font-weight: 700'>体内水分率 (%)</div>", unsafe_allow_html=True)
            with water_input:
                wat = st.number_input("体内水分率 (%)", step=0.05, format="%.2f", label_visibility="collapsed", key="input_water")
            
            if st.form_submit_button("保存"):
                new_data = {"date": str(d), "weight": w, "bmi": b, "fat_pct": f, "visceral": v, "muscle": m, "water": wat}
                updated_records = [
                    record
                    for record in user_info["data"]
                    if record["date"] != str(d)
                ] + [new_data]
                updated_records.sort(key=lambda record: record["date"], reverse=True)
                try:
                    persisted_records = save_persistent_records(
                        user_info["username"],
                        updated_records,
                    )
                except (SupabaseError, TypeError, ValueError) as exc:
                    st.error(f"健康記録を永続保存できません: {exc}")
                    st.stop()
                user_info["data"] = persisted_records
                st.session_state.user = user_info
                st.rerun()

    with col2:
        st.subheader("履歴データ")
        backup_header = f"#BACKUP:{encode_data(build_save_payload(user_info))}\n"
        backup_csv = backup_header + pd.DataFrame(user_info["data"]).to_csv(index=False)

        history_csv = pd.DataFrame(
            normalize_records(user_info["data"]),
            columns=RECORD_COLUMNS,
        ).to_csv(index=False, lineterminator="\n")
        st.download_button(
            label="📄 履歴データCSVをダウンロード",
            data=history_csv.encode("utf-8-sig"),
            file_name=f"health_history_{datetime.now().strftime('%Y%m%d')}.csv",
            mime="text/csv",
            key="history_csv_download_btn",
            use_container_width=True,
        )

        st.download_button(
            label="📥 バックアップファイル(CSV)を保存する",
            data=backup_csv.encode("utf-8-sig"),
            file_name=f"health_data_backup_{datetime.now().strftime('%Y%m%d')}.csv",
            mime="text/csv",
            key="backup_download_btn",
            use_container_width=True,
        )

        uploaded_backup = st.file_uploader(
            "過去データを読み込む",
            type=["csv"],
            key="history_backup_uploader",
            label_visibility="collapsed",
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
                    restored_records = normalize_records(restored["records"])
                    persisted_records = save_persistent_records(
                        user_info["username"],
                        restored_records,
                    )
                    user_info["data"] = persisted_records
                    st.session_state.user = user_info
                    st.rerun()
                except (SupabaseError, TypeError, ValueError) as exc:
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
