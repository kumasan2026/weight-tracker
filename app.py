import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import json
import base64
from datetime import datetime

# Streamlit アプリケーションの基本設定
st.set_page_config(page_title="Professional Health Tracker Pro", layout="wide")

# 1. 開発要件: 印刷用CSSの組み込み (@media print)
st.markdown(
    """
    <style>
    @media print {
        [data-testid="stSidebar"], 
        button, 
        .stButton, 
        header, 
        footer, 
        .embeddedComponent,
        [data-testid="stExpander"] {
            display: none !important;
        }
        .main .block-container {
            padding: 0 !important;
        }
    }
    </style>
    """,
    unsafe_allow_html=True
)

# グラフ描画を完全に独立した関数にして、メインコードのネスト(階層)を消滅させる
def draw_charts(df):
    # 1段目: 体重・BMI・筋肉量
    st.write("**【身体組成トレンド (Weight / BMI / Muscle)】**")
    fig1, ax1_1 = plt.subplots(figsize=(12, 4))
    ax1_1.set_xlabel('Date')
    ax1_1.set_ylabel('Weight / Muscle (kg)', color='tab:blue')
    ax1_1.plot(df['date'], df['weight'], marker='o', color='tab:blue', linewidth=2, label='Weight (kg)')
    ax1_1.plot(df['date'], df['muscle'], marker='^', color='tab:green', linewidth=2, label='Muscle (kg)')
    ax1_1.tick_params(axis='y', labelcolor='tab:blue')
    ax1_1.grid(True, linestyle='--', alpha=0.5)
    
    ax2_1 = ax1_1.twinx()
    ax2_1.set_ylabel('BMI', color='tab:orange')
    ax2_1.plot(df['date'], df['bmi'], marker='s', color='tab:orange', linewidth=2, linestyle='--', label='BMI')
    ax2_1.tick_params(axis='y', labelcolor='tab:orange')
    ax2_1.axhspan(18.5, 25.0, color='green', alpha=0.1, label='Healthy BMI Zone (18.5-25.0)')
    
    lines1, labels1 = ax1_1.get_legend_handles_labels()
    lines2, labels2 = ax2_1.get_legend_handles_labels()
    ax1_1.legend(lines1 + lines2, labels1 + labels2, loc='upper left')
    fig1.tight_layout()
    st.pyplot(fig1)

    st.write("---") 

    # 2段目: 体脂肪率・内臓脂肪・体内水分率
    st.write("**【脂肪・水分トレンド (Fat % / Visceral / Water %)】**")
    fig2, ax2_2 = plt.subplots(figsize=(12, 4))
    ax2_2.set_xlabel('Date')
    ax2_2.set_ylabel('Ratio (%)', color='tab:red')
    ax2_2.plot(df['date'], df['fat_pct'], marker='o', color='tab:red', linewidth=2, label='Body Fat (%)')
    ax2_2.plot(df['date'], df['water'], marker='d', color='tab:cyan', linewidth=2, label='Body Water (%)')
    ax2_2.tick_params(axis='y', labelcolor='tab:red')
    ax2_2.grid(True, linestyle='--', alpha=0.5)
    
    ax2_3 = ax2_2.twinx()
    ax2_3.set_ylabel('Visceral Fat Level', color='tab:purple')
    ax2_3.plot(df['date'], df['visceral'], marker='x', color='tab:purple', linewidth=2, linestyle=':', label='Visceral Fat Lv')
    ax2_3.tick_params(axis='y', labelcolor='tab:purple')
    
    lines3, labels3 = ax2_2.get_legend_handles_labels()
    lines4, labels4 = ax2_3.get_legend_handles_labels()
    ax2_2.legend(lines3 + lines4, labels3 + labels4, loc='upper left')
    fig2.tight_layout()
    st.pyplot(fig2)

# 簡易的なパスワードハッシュ化関数
def simple_hash(password: str) -> str:
    return base64.b64encode(password.encode()).decode()

# URLクエリパラメータによる同期
def load_data_from_url():
    try:
        if "health_data" in st.query_params:
            return json.loads(base64.b64decode(st.query_params["health_data"].encode()).decode())
    except:
        pass
    return {}

def save_data_to_url(data):
    try:
        st.query_params["health_data"] = base64.b64encode(json.dumps(data).encode()).decode()
    except:
        pass

# 状態保持の初期化
stored_data = load_data_from_url()
if "user_db" not in st.session_state:
    st.session_state.user_db = stored_data.get("user_db", {})
if "records" not in st.session_state:
    st.session_state.records = stored_data.get("records", [])
if "logged_in_user" not in st.session_state:
    st.session_state.logged_in_user = None

def sync_to_url():
    sync_data = {"user_db": st.session_state.user_db, "records": st.session_state.records}
    save_data_to_url(sync_data)

# --- 画面描画フロー ---
if st.session_state.logged_in_user is None:
    st.title("Professional Health Tracker Pro")
    
    # 復元フォーム
    st.subheader("データ復元（バックアップCSVをお持ちの方）")
    uploaded_file = st.file_uploader("health_tracker_backup_xxxx.csv を選択", type=["csv"])
    if uploaded_file is not None:
        try:
            content = uploaded_file.getvalue().decode("utf-8")
            first_line = content.splitlines()[0]
            if first_line.startswith("#BACKUP:"):
                raw_b64 = first_line.replace("#BACKUP:", "").strip()
                decoded_data = json.loads(base64.b64decode(raw_b64.encode()).decode())
                st.session_state.user_db = decoded_data.get("user_db", {})
                st.session_state.records = decoded_data.get("records", [])
                sync_to_url()
                st.success("復元しました。下のフォームからログインしてください。")
        except:
            st.error("復元エラーが発生しました。")

    tab1, tab2 = st.tabs(["ログイン", "新規ユーザー登録"])
    with tab1:
        login_user = st.text_input("ユーザー名", key="login_username")
        login_pass = st.text_input("パスワード", type="password", key="login_password")
        if st.button("ログイン"):
            if login_user in st.session_state.user_db and st.session_state.user_db[login_user]["password"] == simple_hash(login_pass):
                st.session_state.logged_in_user = login_user
                st.rerun()
            else:
                st.error("ユーザー名またはパスワードが正しくありません。")
                
    with tab2:
        new_user = st.text_input("新規ユーザー名", key="reg_username")
        new_pass = st.text_input("パスワード", type="password", key="reg_password")
        height = st.number_input("身長 (cm)", min_value=50.0, max_value=250.0, value=170.00, step=0.05, format="%.2f")
        target_weight = st.number_input("目標体重 (kg)", min_value=20.0, max_value=200.0, value=60.00, step=0.05, format="%.2f")
        if st.button("登録"):
            if not new_user or not new_pass:
                st.error("すべての必須項目を入力してください。")
            elif new_user in st.session_state.user_db:
                st.error("このユーザー名は既に存在します。")
            else:
                st.session_state.user_db[new_user] = {"password": simple_hash(new_pass), "height": height, "target_weight": target_weight}
                sync_to_url()
                st.success("登録完了。ログインしてください。")

else:
    current_user = st.session_state.logged_in_user
    user_info = st.session_state.user_db[current_user]
    st.sidebar.title(f"ユーザー: {current_user}")
    
    # CSVエクスポート処理
    user_records = [r for r in st.session_state.records if r["user"] == current_user]
    payload_dict = {"user_db": st.session_state.user_db, "records": st.session_state.records}
    b64_str = base64.b64encode(json.dumps(payload_dict).encode()).decode()
    csv_data = f"#BACKUP:{b64_str}\n"
    if user_records:
        csv_data += pd.DataFrame(user_records).drop(columns=["user"]).to_csv(index=False)
        
    st.sidebar.download_button(
        label="CSVバックアップを保存",
        data=csv_data,
        file_name=f"health_tracker_backup_{datetime.today().strftime('%Y%m%d')}.csv",
        mime="text/csv"
    )

    if st.sidebar.button("ログアウト"):
        st.session_state.logged_in_user = None
        st.rerun()
        
    st.title("高機能健康指標管理システム (Professional Health Tracker Pro)")
    
    if user_records:
        df_alert = pd.DataFrame(user_records)
        df_alert['date'] = pd.to_datetime(df_alert['date'])
        latest_record = df_alert.sort_values(by='date').iloc[-1]
        weight_diff = latest_record['weight'] - user_info['target_weight']
        if weight_diff > 0:
            st.warning(f"目標体重まで あと **{weight_diff:.2f} kg** です。")
        elif weight_diff < 0:
            st.success(f"目標体重達成中！ (目標より **{abs(weight_diff):.2f} kg** 減)")
        else:
            st.info("目標体重をジャストで達成しています！")
    else:
        st.info(f"目標体重: {user_info['target_weight']:.2f} kg (未記録)")
        
    with st.expander("健康指標の新規記録・編集", expanded=True):
        col1, col2, col3 = st.columns(3)
        with col1:
            rec_date = st.date_input("日付", datetime.today())
            weight = st.number_input("体重 (kg)", min_value=20.0, max_value=200.0, value=60.00, step=0.05, format="%.2f")
        with col2:
            fat_pct = st.number_input("体脂肪率 (%)", min_value=1.0, max_value=70.0, value=20.00, step=0.05, format="%.2f")
            visceral = st.number_input("内臓脂肪レベル", min_value=1.0, max_value=30.0, value=5.00, step=0.05, format="%.2f")
        with col3:
            muscle = st.number_input("筋肉量 (kg)", min_value=10.0, max_value=100.0, value=40.00, step=0.05, format="%.2f")
            water = st.number_input("体内水分率 (%)", min_value=10.0, max_value=90.0, value=55.00, step=0.05, format="%.2f")
            
        if st.button("記録を保存する"):
            calculated_bmi = weight / ((user_info['height'] / 100) ** 2)
            new_record = {
                "user": current_user, "date": rec_date.strftime("%Y-%m-%d"), "weight": float(weight),
                "bmi": float(calculated_bmi), "fat_pct": float(fat_pct), "visceral": float(visceral),
                "muscle": float(muscle), "water": float(water)
            }
            st.session_state.records = [r for r in st.session_state.records if not (r["user"] == current_user and r["date"] == new_record["date"])]
            st.session_state.records.append(new_record)
            sync_to_url()
            st.success("データを同期保存しました。")
            st.rerun()

    if user_records:
        df = pd.DataFrame(user_records)
        df['date'] = pd.to_datetime(df['date'])
        df = df.sort_values(by='date').reset_index(drop=True)
        
        st.subheader("履歴データ一覧")
        st.dataframe(df.drop(columns=["user"]), use_container_width=True)
        
        st.subheader("グラフトレンド（横長2段構成）")
        try:
            draw_charts(df)
        except Exception as chart_err:
            st.error(f"グラフ描画エラー: {chart_err}")
    else:
        st.info("データがありません。")
