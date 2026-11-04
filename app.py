import streamlit as st
import pandas as pd
from supabase import create_client, Client
import datetime
from urllib.parse import urlparse

# --- 1. SupabaseベースURLのクレンジング関数 ---
def clean_supabase_url(url_str: str) -> str:
    if not url_str:
        return ""
    url_str = url_str.strip()
    parsed = urlparse(url_str)
    if parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    return url_str

# --- 2. Secretsの読み込みと初期化 ---
def get_supabase_credentials():
    if "supabase" in st.secrets:
        url = st.secrets["supabase"].get("SUPABASE_URL")
        key = st.secrets["supabase"].get("SUPABASE_SERVICE_ROLE_KEY")
        if url and key:
            return clean_supabase_url(url), key.strip()
    return "", ""

SUPABASE_URL, SUPABASE_KEY = get_supabase_credentials()
# (以降、Streamlitによる体重記録・データ履歴表示のUIおよびSupabase連携処理を実装)
