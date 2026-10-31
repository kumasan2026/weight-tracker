import streamlit as st
import pandas as pd
import numpy as np
import datetime
import json
import hashlib
import os
import matplotlib.pyplot as plt

# --- ページ設定 ---
st.set_page_config(
    page_title="Professional Health Tracker Desktop",
    page_icon="⚖️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- アプリ状態の初期化 ---
if 'current_user' not in st.session_state:
    st.session_state.current_user = None

# --- スタイリング (プロ級のカスタムCSS) ---
st.markdown("""
    <style>
    .main { background-color: #f8f9fa; }
    .stButton>button { width: 100%; border-radius: 8px; }
    .metric-card {
        background-color: white;
        padding: 20px;
        border-radius: 12px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.05);
        border-left: 5px solid #4CAF50;
        margin-bottom: 15px;
    }
    .metric-title { font-size: 14px; color: #6c757d; font-weight: bold; }
    .metric-value { font-size: 24px; color: #212529; font-weight: bold; margin-top: 5px; }
    
    @media print {
        .no-print, [data-testid="stSidebar"], button, header { display: none !important; }
        .main { width: 100% !important; background-color: white !important; }
    }
    </style>
""", unsafe_allow_html=True)

# --- ユーティリティ関数（データ保存・読み込みロジック） ---
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def calculate_bmi(weight, height_cm):
    if height_cm > 0:
        return round(weight / ((height_cm / 100) ** 2), 1)
    return 0

def get_data_directory():
    # セッションまたは入力から保存先フォルダを取得（デフォルトは health_app_data）
    target_dir = st.session_state.get("custom_data_dir", "health_app_data").strip()
    if not target_dir:
        target_dir = "health_app_data"
    
    # フォルダが存在しなければ作成を試みる
    try:
        if not os.path.exists(target_dir):
            os.makedirs(target_dir)
        return target_dir
    except Exception as e:
        st.error(f"指定されたフォルダの作成またはアクセスに失敗しました。デフォルトを使用します。エラー: {e}")
        if not os.path.exists("health_app_data"):
            os.makedirs("health_app_data")
        return "health_app_data"

def get_profile_path():
    return os.path.join(get_data_directory(), "profiles.json")

def load_profiles():
    profile_path = get_profile_path()
    if os.path.exists(profile_path):
        try:
            with open(profile_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def save_profiles(profiles):
    profile_path = get_profile_path()
    with open(profile_path, "w", encoding="utf-8") as f:
        json.dump(profiles, f, ensure_ascii=False, indent=4)

def get_user_csv_path(username):
    return os.path.join(get_data_directory(), f"data_{username}.csv")

def load_user_data(username):
    csv_path = get_user_csv_path(username)
    if os.path.exists(csv_path):
        try:
            return pd.read_csv(csv_path)
        except Exception:
            pass
    return pd.DataFrame(columns=["日付", "体重", "BMI", "体脂肪率", "内臓脂肪レベル", "筋肉量", "体内水分率"])

def save_user_data(username, df):
    csv_path = get_user_csv_path(username)
    df.to_csv(csv_path, index=False, encoding="utf-8-sig")

# --- アプリケーションヘッダー ---
st.title("⚖️ 高機能健康指標管理システム (保存先変更対応版)")

# --- ユーザー認証・管理 ---
if st.session_state.current_user is None:
    # ログイン前の画面：最上部で保存先の指定を可能にする
    with st.expander("⚙️ データの保存先設定（別のフォルダに変更したい場合）", expanded=True):
        current_default_abs = os.path.abspath("health_app_data")
        input_dir = st.text_input(
            "保存先フォルダの絶対パスを入力してください（空白の場合は現在のフォルダ内に保存されます）",
            value=st.session_state.get("custom_data_dir", "health_app_data"),
            key="custom_data_dir_input"
        )
        # 入力値をセッションに同期
        st.session_state.custom_data_dir = input_dir
        active_dir = get_data_directory()
        st.info(f"📁 現在有効な保存先フォルダ: `{os.path.abspath(active_dir)}`")

    user_profiles = load_profiles()

    st.subheader("🔑 ログイン / 新規ユーザー登録")
    tab1, tab2 = st.tabs(["ログイン", "新規登録"])
    
    with tab1:
        login_name = st.text_input("ユーザー名", key="login_name")
        login_pass = st.text_input("パスワード", type="password", key="login_pass")
        if st.button("ログイン", key="login_btn"):
            hashed = hash_password(login_pass)
            if login_name in user_profiles and user_profiles[login_name]['password'] == hashed:
                st.session_state.current_user = login_name
                st.success(f"おかえりなさい、{login_name} さん！データを読み込みました。")
                st.rerun()
            else:
                st.error("ユーザー名またはパスワードが正しくありません。（保存先フォルダが合っているか確認してください）")
                
    with tab2:
        reg_name = st.text_input("ご希望のユーザー名 (個別管理用)", key="reg_name")
        reg_pass = st.text_input("パスワードを設定", type="password", key="reg_pass")
        reg_height = st.number_input("身長 (cm) *必須", min_value=50.0, max_value=250.0, value=170.0, step=0.1, key="reg_height")
        reg_target = st.number_input("目標体重 (kg) *必須", min_value=20.0, max_value=200.0, value=60.0, step=0.1, key="reg_target")
        
        if st.button("アカウントを作成して初期設定を完了する", key="reg_btn"):
            if not reg_name or not reg_pass:
                st.error("すべての必須項目を入力してください。")
            elif reg_name in user_profiles:
                st.error("このユーザー名は既に存在します。")
            else:
                user_profiles[reg_name] = {
                    "password": hash_password(reg_pass),
                    "height": reg_height,
                    "target_weight": reg_target
                }
                save_profiles(user_profiles)
                # 空のCSVを初期作成
                empty_df = pd.DataFrame(columns=["日付", "体重", "BMI", "体脂肪率", "内臓脂肪レベル", "筋肉量", "体内水分率"])
                save_user_data(reg_name, empty_df)
                
                st.session_state.current_user = reg_name
                st.success("登録完了！指定されたデータフォルダにアカウントを作成しました。")
                st.rerun()

else:
    user = st.session_state.current_user
    user_profiles = load_profiles()
    profile = user_profiles[user]
    
    # 有効なフォルダから該当ユーザーのCSVを自動ロード
    df_user = load_user_data(user)

    # サイドバー：アカウント＆保存先表示
    with st.sidebar:
        st.markdown(f"### 👤 ログイン中: **{user}**")
        if st.button("🔒 安全にログアウト", key="logout_btn"):
            st.session_state.current_user = None
            st.rerun()
        st.markdown("---")
        
        # ログイン後もサイドバーから現在の保存先を確認・変更可能
        st.markdown("### ⚙️ 現在の保存先設定")
        input_dir_sidebar = st.text_input(
            "保存先フォルダパス",
            value=st.session_state.get("custom_data_dir", "health_app_data"),
            key="custom_data_dir_sidebar"
        )
        if input_dir_sidebar != st.session_state.get("custom_data_dir"):
            st.session_state.custom_data_dir = input_dir_sidebar
            st.rerun()
            
        st.success(f"📁 データ保存先:\n`{os.path.abspath(get_data_directory())}`")

    # メイン表示部
    # 1. フルデータ記録 ＆ リアルタイム自動計算
    st.subheader("📝 本日の数値を記録・更新")
    col1, col2, col3 = st.columns(3)
    with col1:
        in_date = st.date_input("記録日", datetime.date.today())
        in_weight = st.number_input("体重 (kg)", min_value=20.0, max_value=200.0, value=65.0, step=0.1)
    with col2:
        calc_bmi = calculate_bmi(in_weight, profile['height'])
        st.metric(label="現在のリアルタイムBMI", value=calc_bmi)
        in_fat = st.number_input("体脂肪率 (%)", min_value=1.0, max_value=70.0, value=20.0, step=0.1)
    with col3:
        in_visceral = st.number_input("内臓脂肪レベル", min_value=1, max_value=30, value=5, step=1)
        in_muscle = st.number_input("筋肉量 (kg)", min_value=10.0, max_value=100.0, value=45.0, step=0.1)
        in_water = st.number_input("体内水分率 (%)", min_value=10.0, max_value=90.0, value=55.0, step=0.1)

    if st.button("✨ この健康指標データを安全に保存する", type="primary"):
        new_row = {
            "日付": str(in_date), "体重": in_weight, "BMI": calc_bmi,
            "体脂肪率": in_fat, "内臓脂肪レベル": in_visceral, "筋肉量": in_muscle, "体内水分率": in_water
        }
        
        # 上書き処理：もし同じ日付がすでに存在したら古い方を消す
        if not df_user.empty and str(in_date) in df_user["日付"].values:
            df_user = df_user[df_user["日付"] != str(in_date)]
        
        df_new = pd.concat([df_user, pd.DataFrame([new_row])], ignore_index=True).sort_values("日付")
        
        # 指定されたフォルダのCSVファイルに全自動上書き保存！
        save_user_data(user, df_new)
        st.success("データを指定フォルダに自動保存しました！")
        st.rerun()

    st.markdown("---")

    # 2. ダッシュボード & 目標値の表示
    if not df_user.empty:
        latest = df_user.iloc[-1]
        current_weight = latest["体重"]
        target_weight = profile["target_weight"]
        diff = round(current_weight - target_weight, 1)
        
        if diff > 0:
            st.error(f"🎯 **目標体重（{target_weight} kg）まで あと {diff} kg** です。")
        elif diff == 0:
            st.success(f"🎉 **目標体重（{target_weight} kg）をぴったり達成中！素晴らしい状態です！**")
        else:
            st.info(f"✨ **目標体重（{target_weight} kg）をクリアしています！（マイナス {-diff} kg）**")

        m1, m2, m3, m4 = st.columns(4)
        with m1:
            st.markdown(f'<div class="metric-card"><div class="metric-title">最新の体重</div><div class="metric-value">{current_weight} kg</div></div>', unsafe_allow_html=True)
        with m2:
            st.markdown(f'<div class="metric-card"><div class="metric-title">最新のBMI</div><div class="metric-value">{latest["BMI"]}</div></div>', unsafe_allow_html=True)
        with m3:
            st.markdown(f'<div class="metric-card"><div class="metric-title">体脂肪率</div><div class="metric-value">{latest["体脂肪率"]} %</div></div>', unsafe_allow_html=True)
        with m4:
            st.markdown(f'<div class="metric-card"><div class="metric-title">筋肉量</div><div class="metric-value">{latest["筋肉量"]} kg</div></div>', unsafe_allow_html=True)

        st.markdown("### 📈 体重 ＆ BMI トレンド (健康ゾーン可視化)")
        
        fig, ax1 = plt.subplots(figsize=(11, 4), dpi=150)
        dates = pd.to_datetime(df_user["日付"])
        
        color1 = '#1f77b4'
        ax1.set_ylabel('Weight (kg)', color=color1, fontweight='bold')
