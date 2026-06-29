import os
import pandas as pd
import streamlit as st
import plotly.express as px

# Dashboard UI configurations
st.set_page_config(page_title="Ransomware AI Warning", layout="wide", page_icon="🛡️")

if "learning_status" not in st.session_state:
    st.session_state.learning_status = None

st.markdown("""
    <style>
        .block-container { padding-top: 1rem; padding-bottom: 1rem; }
        .stTabs [data-baseweb="tab-list"] { gap: 10px; }
        .stTabs [data-baseweb="tab"] { height: 50px; font-weight: bold; }
    </style>
""", unsafe_allow_html=True)

st.title("Ransomware AI Warning & Behavior Analysis")
st.markdown("Real-time monitoring and threat mitigation interface powered by Ensemble Machine Learning.")

BASE_DIR = r"D:\iam"
LOG_FILE = os.path.join(BASE_DIR, 'data', 'soc_logs.csv')

def load_data():
    if not os.path.exists(LOG_FILE):
        return pd.DataFrame()
    try:
        df = pd.read_csv(LOG_FILE, names=['Timestamp', 'Filename', 'Status', 'Verdict', 'RF', 'XGB', 'IF', 'LGBM'], header=None)
        df['Timestamp_dt'] = pd.to_datetime(df['Timestamp'], errors='coerce')
        
        df['Status'] = df['Status'].str.strip()
        df['Status'] = df['Status'].replace({'Safe': 'Safe (Benign)', 'Malware Detected': 'Malware (Ransomware)'})
        
        for col in ['RF', 'XGB', 'IF', 'LGBM']:
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0.0)
        return df.sort_values(by='Timestamp_dt')
    except Exception:
        return pd.DataFrame()

@st.fragment(run_every=2)
def render_dashboard_metrics():
    df = load_data()
    tab1, tab2, tab3 = st.tabs(["Overview & Timeline", "Early Detection Alerts", "Raw SOC Logs"])

    # TAB 1: OVERVIEW & TIMELINE
    with tab1:
        if not df.empty:
            st.subheader("Risk Score Timeline by 4 Algorithms")
            df_plot = df.copy().reset_index()
            df_plot.rename(columns={'index': 'Event Index'}, inplace=True)
            
            fig_risk = px.line(
                df_plot,
                x="Event Index",
                y=["RF", "XGB", "IF", "LGBM"],
                labels={"value": "Risk Score (%)", "variable": "Algorithms"},
                title="Risk Scores Trend Over Monitored Events",
                markers=True
            )
            fig_risk.update_layout(hovermode="x unified")
            st.plotly_chart(fig_risk, use_container_width=True)
            
            st.markdown("---")
            st.subheader("Detection Summary Distribution")
            
            color_map = {'Safe (Benign)': '#00CC66', 'Malware (Ransomware)': '#FF3333'}
            fig_pie = px.pie(df, names='Status', title='System Status Proportional Share', color='Status', color_discrete_map=color_map)
            st.plotly_chart(fig_pie, use_container_width=True)
        else:
            st.info("Awaiting live thread signals from 'realtime_monitor.py'...")

    # TAB 2: EARLY DETECTION ALERTS
    with tab2:
        st.subheader("Critical Risk Alerts Log")
        if not df.empty:
            malicious_files = df[df['Status'].str.contains('Malware|Ransomware', na=False, case=False)]
            col_metrics, col_alerts_box = st.columns([1, 2])
            
            with col_metrics:
                st.metric(
                    label="Total Intercepted Threats", 
                    value=len(malicious_files),
                    delta="Critical" if len(malicious_files) > 0 else "Clear",
                    delta_color="inverse"
                )
            
            with col_alerts_box:
                if not malicious_files.empty:
                    for _, row in malicious_files.tail(4).iterrows():
                        st.error(f"CRITICAL WARNING: Threat detected [{row['Verdict']}] at file: {row['Filename']} (Scores -> RF: {row['RF']}% | XGB: {row['XGB']}%)")
                else:
                    st.success("Endpoint secure. No suspicious behavioral patterns flagged.", icon="✅")
                    
            st.markdown("### Malicious Incidents Overview Matrix")
            st.dataframe(malicious_files[['Timestamp', 'Filename', 'Verdict', 'RF', 'XGB', 'IF', 'LGBM']], use_container_width=True, hide_index=True)
        else:
            st.info("No recorded malicious events available.")

    # TAB 3: RAW SOC LOGS
    with tab3:
        st.subheader("Full SOC Logs Feature Matrix")
        if not df.empty:
            def style_status_row(val):
                if 'Malware' in str(val) or 'Ransomware' in str(val):
                    return 'color: #FF3333; font-weight: bold;'
                elif 'Safe' in str(val) or 'Benign' in str(val):
                    return 'color: #00CC66; font-weight: bold;'
                return ''
            
            display_df = df.copy().drop(columns=['Timestamp_dt'], errors='ignore')
            st.dataframe(display_df.style.map(style_status_row, subset=['Status']), use_container_width=True, hide_index=True)
        else:
            st.write("System audit data-grid is currently unallocated.")

render_dashboard_metrics()

# SYSTEM INTERACTION RADAR
st.markdown("---")
st.header("Adaptive Feedback Control Center")

if st.session_state.learning_status:
    status_type, msg = st.session_state.learning_status
    if status_type == "success":
        st.success(msg)
    else:
        st.error(msg)
    
    if st.button("Clear Notification View"):
        st.session_state.learning_status = None
        st.rerun()

st.markdown("Interactive oversight matrix for manual baseline recalibration and zero-day threat verification.")

current_df = load_data()
available_files = []

if not current_df.empty:
    monitor_dir = os.path.join(BASE_DIR, "giamsat")
    for fname in current_df['Filename'].dropna().unique():
        full_p = os.path.join(monitor_dir, fname)
        if os.path.exists(full_p):
            available_files.append(full_p)

available_files = [f for f in list(set(available_files)) if os.path.exists(f)]

if len(available_files) == 0:
    st.info("System observation cache empty. Awaiting targeted telemetry events.")
else:
    with st.form("adaptive_learning_flexible_form", clear_on_submit=False):
        selected_file_path = st.selectbox(
            "Target monitored payload object:",
            options=available_files,
            format_func=lambda x: f"[{os.path.basename(x)}] located at {os.path.dirname(x)}"
        )
        
        learning_type = st.selectbox(
            "Assign system feedback response vector:",
            options=["Enforce Whitelist Constraint (Mark as Safe)", "Trigger Zero-Day Optimization (Mark as Ransomware)"]
        )
            
        btn_submit_learning = st.form_submit_button("Initiate Active Learning Loop")

        if btn_submit_learning and selected_file_path:
            try:
                from realtime_monitor import learn_from_live_event
                
                is_malware_label = True if "Zero-Day" in learning_type else False
                status_msg = "Malware Class (Label 1)" if is_malware_label else "Safe Class (Label 0)"
                
                with st.spinner(f"Running partial fits and retraining classification arrays for target: {os.path.basename(selected_file_path)}..."):
                    success = learn_from_live_event(selected_file_path, is_malware=is_malware_label)
                    
                    if success:
                        st.session_state.learning_status = (
                            "success",
                            f"Recalibration sequence finished. AI arrays adjusted to target class: {status_msg} for payload: {os.path.basename(selected_file_path)}."
                        )
                    else:
                        st.session_state.learning_status = ("error", "Pipeline training aborted. Ensure raw vector matrices inside data_file.csv match schema targets.")
                st.rerun()
            except Exception as e:
                st.error(f"Active connection link broken: {e}")