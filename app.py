import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import json
import base64
from datetime import datetime

# ==========================================
# 1. グラフ・フォントのグローバル設定
# ==========================================
plt.rcParams['font.family'] = ['sans-serif']
plt.rcParams['font.sans-serif'] = ['Hiragino Maru Gothic Pro', 'Yu Gothic', 'Meiryo', 'TakaoExGothic', 'DejaVu Sans', 'IPAexGothic']

# グラフ内の文字サイズ調整
plt.rcParams['font.size'] = 14  
plt.rcParams['axes.titlesize'] = 16
plt.rcParams['axes.labelsize'] = 14
plt.rcParams['xtick.labelsize'] = 12
plt.rcParams['ytick.labelsize'] = 12
plt.rcParams['legend.fontsize'] = 12

# ==========================================
# 2. ユーティリティ・データ処理関数
# ==========================================

def encrypt_data(data_dict):
    try:
        json_str = json.dumps(data_dict, ensure_ascii=False)
        return base64.b64encode(json_str.encode('utf-8')).decode('utf-8')
    except:
        return ""

def decrypt_data(b64_str):
    try:
        missing_padding = len(b64_str) % 4
        if missing_padding:
            b64_str += '=' * (4 - missing_padding)
        json_str = base64.b64decode(b64_str.encode('utf-8')).decode('utf-8')
        return json.loads(json_str)
    except:
        return {}

def parse_backup_csv(uploaded_file):
    if uploaded_file is None:
        return None
    try:
        bytes_data = uploaded_file.getvalue()
        text_data = bytes_data.decode("utf-8-sig").replace("\r\n", "\n")
        lines = [line.strip() for line in text_data.split("\n") if line.strip()]
        if not lines:
            return None
        
        for line in lines:
            if "#BACKUP:" in line:
                b64_data = line.split("#BACKUP:")[-1].strip()
                return decrypt_data(b64_data)
    except:
        pass
    return None

def add_point_labels(ax, dates, values, offset, vertical_alignment):
    for date, value in zip(dates, values):
        if pd.notna(value):
            ax.text(
                date,
                value + offset,
                f"{value:.2f}",
                ha="center",
                va=vertical_alignment,
                fontsize=8
            )

# ==========================================
# 3. メインアプリケーション設定
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

if "user" not in st.session_state:
    query_params = st.query_params
    param_str = query_params.get("health_data", "")
    st.session_state.user = decrypt_data(param_str) if param_str else {}

is_logged_in = "username" in st.session_state.user

if not is_logged_in:
    st.subheader("ログイン / バックアップ復元")
    
    uploaded_file = st.file_uploader("バックアップCSVファイルをここにドラッグ＆ドロップ", type=["csv"])
    if uploaded_file is not None:
        restored = parse_backup_csv(uploaded_file)
        if restored and "records" in restored:
            st.session_state.user = {
                "username": "tomato",
                "data": restored["records"]
            }
            st.query_params["health_data"] = encrypt_data(restored)
            st.success("ログイン成功！データを復元しました。")
            st.rerun()
        else:
            st.error("Invalid backup file format. Please make sure it includes the proper header.")

    with st.form("login"):
        user_input = st.text_input("ユーザー名", value="tomato")
        pass_input = st.text_input("パスワード", type="password")
        if st.form_submit_button("サインイン"):
            st.session_state.user = {"username": user_input, "data": []}
            st.rerun()
else:
    user_info = st.session_state.user
    st.sidebar.title(f"👤 {user_info['username']}")
    
    if st.sidebar.button("サインアウト"):
        st.session_state.user = {}
        st.query_params.clear()
        st.rerun()

    # 【確実なレイアウト修正】「本日の記録」側を細め（2）に固定し、「履歴データ」側を広め（3）に指定
    col1, col2 = st.columns([2, 3])
    
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
                w = st.number_input("体重 (kg)", value=70.0, step=0.05, format="%.2f", label_visibility="collapsed")

            bmi_label, bmi_input = st.columns([1, 2])
            with bmi_label:
                st.markdown("<div style='height: 48px; display: flex; align-items: center; font-weight: 700'>BMI</div>", unsafe_allow_html=True)
            with bmi_input:
                b = st.number_input("BMI", value=22.0, step=0.05, format="%.2f", label_visibility="collapsed")

            fat_label, fat_input = st.columns([1, 2])
            with fat_label:
                st.markdown("<div style='height: 48px; display: flex; align-items: center; font-weight: 700'>体脂肪率 (%)</div>", unsafe_allow_html=True)
            with fat_input:
                f = st.number_input("体脂肪率 (%)", value=20.0, step=0.05, format="%.2f", label_visibility="collapsed")

            visceral_label, visceral_input = st.columns([1, 2])
            with visceral_label:
                st.markdown("<div style='height: 48px; display: flex; align-items: center; font-weight: 700'>内臓脂肪レベル</div>", unsafe_allow_html=True)
            with visceral_input:
                v = st.number_input("内臓脂肪レベル", value=5.0, step=0.05, format="%.2f", label_visibility="collapsed")

            muscle_label, muscle_input = st.columns([1, 2])
            with muscle_label:
                st.markdown("<div style='height: 48px; display: flex; align-items: center; font-weight: 700'>筋肉量 (kg)</div>", unsafe_allow_html=True)
            with muscle_input:
                m = st.number_input("筋肉量 (kg)", value=50.0, step=0.05, format="%.2f", label_visibility="collapsed")

            water_label, water_input = st.columns([1, 2])
            with water_label:
                st.markdown("<div style='height: 48px; display: flex; align-items: center; font-weight: 700'>体内水分率 (%)</div>", unsafe_allow_html=True)
            with water_input:
                wat = st.number_input("体内水分率 (%)", value=55.0, step=0.05, format="%.2f", label_visibility="collapsed")
            
            if st.form_submit_button("保存"):
                new_data = {"date": str(d), "weight": w, "bmi": b, "fat": f, "visceral": v, "muscle": m, "water": wat}
                user_info["data"] = [r for r in user_info["data"] if r["date"] != str(d)] + [new_data]
                user_info["data"].sort(key=lambda x: x["date"], reverse=True)
                st.session_state.user = user_info
                
                full_save = {
                    "user_db": {"tomato": {"password": "cHVjYQ==", "height": 174.0, "target_weight": 65.0}},
                    "records": user_info["data"]
                }
                st.query_params["health_data"] = encrypt_data(full_save)
                st.rerun()

    with col2:
        st.subheader("履歴データ")
        if user_info["data"]:
            history_df = pd.DataFrame(user_info["data"])
            history_df = history_df.sort_values("date", ascending=False).reset_index(drop=True)
            
            full_save_data = {
                "user_db": {"tomato": {"password": "cHVjYQ==", "height": 174.0, "target_weight": 65.0}},
                "records": user_info["data"]
            }
            encrypted_header = f"#BACKUP:{encrypt_data(full_save_data)}\n"
            csv_body = history_df.to_csv(index=False)
            final_backup_string = encrypted_header + csv_body
            
            st.download_button(
                label="📥 バックアップファイル(CSV)を保存する",
                data=final_backup_string.encode('utf-8-sig'),
                file_name=f"health_data_backup_{datetime.now().strftime('%Y%m%d')}.csv",
                mime="text/csv",
                key="backup_download_btn"
            )
            
            display_cols = ["date", "weight", "bmi", "fat", "visceral", "muscle", "water"]
            existing_cols = [c for c in display_cols if c in history_df.columns]
            display_df = history_df[existing_cols].copy()
            
            display_df = display_df.rename(columns={
                "date": "日付", "weight": "体重(kg)", "bmi": "BMI", 
                "fat": "体脂肪率(%)", "visceral": "内臓脂肪", 
                "muscle": "筋肉量(kg)", "water": "体内水分率(%)"
            })
            
            # フォーム全体のサイズ感にピッタリ連動する適正な高さに固定
            st.dataframe(display_df, use_container_width=True, height=535, hide_index=True)
        else:
            st.info("データがありません。")

    st.write("---")
    
    # 分析ダッシュボード（不具合の原因を完全に排除し、確実に表示される上下二段構成）
    st.subheader("📊 分析ダッシュボード")
    if user_info["data"]:
        df = pd.DataFrame(user_info["data"]).sort_values("date")
        df["date"] = pd.to_datetime(df["date"])
        
        # 旧データ互換用マージ
        if "fat_pct" in df.columns and "fat" not in df.columns:
            df["fat"] = df["fat_pct"]
        
        # 一段目グラフ：体重・筋肉量・体内水分率
        fig1, ax1 = plt.subplots(figsize=(16, 5))
        ax1.plot(df["date"], df.get("weight", pd.Series(dtype='float64')), marker="o", label="体重 (kg)", color="#1f77b4", linewidth=3, markersize=8)
        ax1.plot(df["date"], df.get("muscle", pd.Series(dtype='float64')), marker="^", label="筋肉量 (kg)", color="#2ca02c", linewidth=3, markersize=8)
        ax1.plot(df["date"], df["water"], marker="s", label="体内水分率 (%)", color="#17becf", linewidth=3, markersize=8)
        ax1.margins(y=0.15)
        label_offset = (ax1.get_ylim()[1] - ax1.get_ylim()[0]) * 0.025
        add_point_labels(ax1, df["date"], df.get("weight", pd.Series(dtype='float64')), label_offset, "bottom")
        add_point_labels(ax1, df["date"], df.get("muscle", pd.Series(dtype='float64')), -label_offset, "top")
        add_point_labels(ax1, df["date"], df["water"], label_offset * 2, "bottom")
        ax1.set_title("体重・筋肉量・体内水分率の推移", pad=15, fontweight='bold')
        ax1.set_xlabel("日付")
        ax1.grid(True, linestyle="--", alpha=0.5)
        ax1.legend(loc="upper left")
        st.pyplot(fig1)
        plt.close(fig1)
        
        st.write("") 
        
        # 二段目グラフ：BMI・体脂肪・内臓脂肪
        fig2, ax2 = plt.subplots(figsize=(16, 5))
        ax2.plot(df["date"], df.get("bmi", pd.Series(dtype='float64')), marker="o", color="#ff7f0e", label="BMI", linewidth=3, markersize=8)
        ax2.plot(df["date"], df.get("fat", pd.Series(dtype='float64')), marker="s", color="#d62728", label="体脂肪率 (%)", linewidth=3, markersize=8)
        ax2.plot(df["date"], df.get("visceral", pd.Series(dtype='float64')), marker="^", color="#9467bd", label="内臓脂肪レベル", linewidth=3, markersize=8)
        ax2.margins(y=0.15)
        label_offset = (ax2.get_ylim()[1] - ax2.get_ylim()[0]) * 0.025
        add_point_labels(ax2, df["date"], df.get("bmi", pd.Series(dtype='float64')), label_offset, "bottom")
        add_point_labels(ax2, df["date"], df.get("fat", pd.Series(dtype='float64')), -label_offset, "top")
        add_point_labels(ax2, df["date"], df.get("visceral", pd.Series(dtype='float64')), label_offset * 2, "bottom")
        ax2.set_title("BMI・体脂肪・内臓脂肪の推移", pad=15, fontweight='bold')
        ax2.set_xlabel("日付")
        ax2.grid(True, linestyle="--", alpha=0.5)
        ax2.legend(loc="upper left")
        st.pyplot(fig2)
