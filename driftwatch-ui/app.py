import sqlite3
import json
import pandas as pd
import streamlit as st
import backend.db_manager as db_manager

# --- Page Configuration ---
st.set_page_config(
    page_title="DriftWatch | Incidents Dashboard",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Stitch Design System (CSS Injection) ---
st.markdown("""
    <style>
        /* Import Fonts */
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;900&family=JetBrains+Mono:wght@400;500&display=swap');

        /* Base Theme - Stitch Variables */
        .stApp { background-color: #09090b; color: #e5e1e4; font-family: 'Inter', sans-serif; }
        
        /* Sidebar Override */
        [data-testid="stSidebar"] { background-color: #0e0e10 !important; border-right: 1px solid #2a2a2c; }
        .sidebar-logo { font-family: 'Inter', sans-serif; font-weight: 900; font-size: 1.5rem; color: #4cd7f6; letter-spacing: -1px; margin-bottom: 0px; }
        .sidebar-sub { font-family: 'JetBrains Mono', monospace; font-size: 0.7rem; color: #869397; text-transform: uppercase; letter-spacing: 2px; }
        
        /* Top Navigation Header */
        .top-header { display: flex; align-items: center; border-bottom: 1px solid #2a2a2c; padding-bottom: 15px; margin-bottom: 20px; }
        .top-header h2 { margin: 0; font-weight: 900; color: #4cd7f6; font-size: 1.25rem; }
        .top-header .divider { height: 20px; width: 1px; background-color: #3d494c; margin: 0 15px; }
        .top-header .subtitle { font-family: 'Inter', sans-serif; font-weight: 700; font-size: 0.7rem; letter-spacing: 0.05em; color: #e5e1e4; text-transform: uppercase; }
        .status-pill { background-color: rgba(6,182,212,0.1); border: 1px solid #06b6d4; padding: 4px 10px; font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; color: #4cd7f6; display: flex; align-items: center; gap: 8px; margin-left: auto; }
        .status-dot { width: 8px; height: 8px; background-color: #06b6d4; border-radius: 50%; }

        /* KPI Metric Cards (Stitch Style) */
        [data-testid="stMetric"] { background-color: #18181b; border: 1px solid #27272a; padding: 15px; border-radius: 0px; transition: border-color 0.2s; }
        [data-testid="stMetric"]:hover { border-color: #06b6d4; }
        [data-testid="stMetricLabel"] { font-family: 'Inter', sans-serif; font-weight: 700; font-size: 0.7rem; letter-spacing: 0.05em; color: #bcc9cd; text-transform: uppercase; margin-bottom: 15px; }
        [data-testid="stMetricValue"] { font-family: 'Inter', sans-serif; font-size: 2rem; font-weight: 700; color: #e5e1e4; }
        
        /* Table Structure */
        .data-table-header { display: flex; font-family: 'Inter', sans-serif; font-weight: 700; font-size: 0.7rem; letter-spacing: 0.05em; color: #869397; text-transform: uppercase; border-bottom: 1px solid #27272a; padding-bottom: 8px; margin-bottom: 8px; }
        .data-row { display: flex; font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; border-bottom: 1px solid #27272a; padding: 12px 0; align-items: center; background-color: #1c1c1f; transition: background-color 0.2s; border-left: 2px solid transparent; }
        .data-row:hover { background-color: #2a2a2c; border-left: 2px solid #06b6d4; }
        .col-time { width: 25%; color: #869397; padding-left: 10px; }
        .col-id { width: 35%; color: #06b6d4; }
        .col-event { width: 25%; color: #e5e1e4; }
        .col-tags { width: 15%; }
        
        /* Tags & Pills */
        .tag-pill { border: 1px solid #3d494c; color: #bcc9cd; font-size: 0.65rem; padding: 2px 6px; text-transform: uppercase; margin-right: 4px; font-family: 'Inter', sans-serif; background: transparent; }
        .critical-pill { background-color: rgba(244,63,94,0.1); border: 1px solid #f43f5e; color: #ffb4ab; font-size: 0.65rem; padding: 2px 6px; text-transform: uppercase; font-weight: 700; letter-spacing: 1px; }

        /* Detail Panel */
        .detail-panel { background-color: #1c1c1f; border: 1px solid #3f3f46; position: relative; padding-top: 20px; }
        .detail-accent-bar { height: 4px; width: 100%; background-color: #f43f5e; position: absolute; top: 0; left: 0; }
        .detail-title { font-family: 'Inter', sans-serif; font-size: 1.25rem; font-weight: 600; color: #e5e1e4; margin: 10px 20px 0 20px; word-break: break-all; }
        .detail-sub { font-family: 'JetBrains Mono', monospace; font-size: 0.7rem; color: #bcc9cd; margin: 0 20px 20px 20px; border-bottom: 1px solid #3f3f46; padding-bottom: 15px; }
        
        .section-heading { font-family: 'Inter', sans-serif; font-weight: 700; font-size: 0.7rem; letter-spacing: 0.05em; color: #869397; text-transform: uppercase; border-bottom: 1px solid #3f3f46; padding-bottom: 4px; margin: 20px 20px 10px 20px; }
        .threat-text { font-family: 'Inter', sans-serif; font-size: 0.85rem; color: #e5e1e4; line-height: 1.5; margin: 0 20px; }
        
        /* JSON Block */
        .json-block { background-color: #000000; border: 1px solid #27272a; padding: 15px; margin: 0 20px 20px 20px; overflow-x: auto; font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; color: #e5e1e4; }
        .json-add { background-color: rgba(78,222,163,0.15); color: #4edea3; border-left: 2px solid #4edea3; display: block; padding-left: 5px; }
        .json-sub { background-color: rgba(244,63,94,0.15); color: #ffb4ab; border-left: 2px solid #f43f5e; display: block; padding-left: 5px; }
        
        /* Action Buttons */
        .btn-row { background-color: #131315; border-top: 1px solid #3f3f46; padding: 15px 20px; display: flex; justify-content: flex-end; gap: 10px; margin-top: 20px; }
        .btn-ignore { background: transparent; border: 1px solid #3f3f46; color: #e5e1e4; font-family: 'Inter', sans-serif; font-size: 0.7rem; font-weight: 700; padding: 8px 16px; cursor: pointer; }
        .btn-remediate { background: #06b6d4; border: 1px solid #06b6d4; color: #000000; font-family: 'Inter', sans-serif; font-size: 0.7rem; font-weight: 700; padding: 8px 16px; cursor: pointer; }
    </style>
""", unsafe_allow_html=True)

# --- Data Loading & Threat Logic ---
@st.cache_data(ttl=5)
def load_data():
    conn = sqlite3.connect(db_manager.DB_NAME)
    drifts = pd.read_sql_query("SELECT * FROM drift_logs ORDER BY id DESC", conn)
    snaps = pd.read_sql_query("SELECT * FROM snapshots ORDER BY id DESC", conn)
    conn.close()
    return drifts, snaps

def get_threat_context(row):
    details = str(row.get('details', '')).lower()
    if "22" in details or "ssh" in details:
        return "SSH Port 22 was modified to allow inbound connections from 0.0.0.0/0. High probability of brute-force attacks and unauthorized access."
    elif any(port in details for port in ["5432", "3306", "3389"]):
        return "Public access block removed for critical database/management port. Exposes highly sensitive data archives to public read access. High probability of PII data exfiltration violating GDPR Art. 32."
    return "Network access rules modified outside of approved baseline. Violates least privilege."

drift_df, snapshot_df = load_data()

# --- Sidebar (Stitch Style) ---
with st.sidebar:
    st.markdown("""
        <div class="sidebar-logo">DRIFTWATCH</div>
        <div class="sidebar-sub">Cloud Security</div>
        <br>
    """, unsafe_allow_html=True)
    st.button("🎯 Quick Scan", use_container_width=True)
    st.markdown("---")
    st.markdown("🪟 Overview")
    st.markdown("🛡️ **Incidents**")
    st.markdown("📦 Assets")
    st.markdown("📋 Compliance Frameworks")
    st.markdown("⚙️ Settings")

# --- Top Header ---
st.markdown("""
    <div class="top-header">
        <h2>DriftWatch</h2>
        <div class="divider"></div>
        <div class="subtitle">Cloud Security Posture Management</div>
        <div class="status-pill">
            <div class="status-dot"></div>
            Monitoring: AWS us-east-1
        </div>
    </div>
""", unsafe_allow_html=True)

# --- Executive Metrics Row ---
col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("Monitored Assets", len(snapshot_df))
with col2:
    st.metric("Active Drifts", len(drift_df))
with col3:
    st.metric("Critical Infra Risks", len(drift_df[drift_df['cis_control'].str.contains('CIS 5.2|CIS 5.1', na=False)]) if not drift_df.empty else 0)
with col4:
    st.metric("Privacy Violations", len(drift_df[drift_df['gdpr_control'].str.contains('GDPR', na=False)]) if not drift_df.empty else 0)

st.write("")

# --- Filters ---
f_col1, f_col2, f_col3 = st.columns([2, 1, 1])
with f_col1:
    search_query = st.text_input("Search", placeholder="Search resource ID...", label_visibility="collapsed")
with f_col2:
    framework_filter = st.selectbox("Framework", ["All Frameworks", "GDPR", "DPDPA", "CIS", "ISO 27001"], label_visibility="collapsed")

# Apply Filters
filtered_df = drift_df.copy()
if not filtered_df.empty:
    if framework_filter != "All Frameworks":
        filtered_df = filtered_df[
            filtered_df['gdpr_control'].str.contains(framework_filter, case=False, na=False) |
            filtered_df['dpdpa_control'].str.contains(framework_filter, case=False, na=False) |
            filtered_df['cis_control'].str.contains(framework_filter, case=False, na=False) |
            filtered_df['iso_control'].str.contains(framework_filter, case=False, na=False)
        ]
    if search_query:
        filtered_df = filtered_df[filtered_df['resource_id'].str.contains(search_query, case=False)]

# --- Layout Split: Data Table & Incident Detail ---
if not filtered_df.empty:
    list_col, detail_col = st.columns([1.3, 1])
    
    with list_col:
        # Table Header
        st.markdown("""
        <div class="data-table-header">
            <div class="col-time">TIMESTAMP</div>
            <div class="col-id">RESOURCE ID</div>
            <div class="col-event">EVENT TYPE</div>
            <div class="col-tags">TAGS</div>
        </div>
        """, unsafe_allow_html=True)
        
        # Table Rows
        for idx, row in filtered_df.iterrows():
            st.markdown(f"""
            <div class="data-row">
                <div class="col-time">{row['timestamp'][:19]}Z</div>
                <div class="col-id">{row['resource_id']}</div>
                <div class="col-event"><span style="color:#f43f5e;font-size:10px;">■</span> {row['event_type']}</div>
                <div class="col-tags">
                    <span class="tag-pill">CIS</span>
                    <span class="tag-pill">GDPR</span>
                </div>
            </div>
            """, unsafe_allow_html=True)

    with detail_col:
        # We display details for the first item in the filtered list
        selected_row = filtered_df.iloc[0]
        context = get_threat_context(selected_row)
        
        # Convert JSON safely for display
        try:
            formatted_json = json.dumps(json.loads(selected_row['details']), indent=2)
            # Simple diff simulation for the UI
            if "22" in formatted_json or "5432" in formatted_json:
                formatted_json = formatted_json.replace('"CidrIp": "0.0.0.0/0"', '<span class="json-sub">- "CidrIp": "10.0.0.0/16"</span>\n<span class="json-add">+ "CidrIp": "0.0.0.0/0"</span>')
        except:
            formatted_json = selected_row['details']
            
        st.markdown(f"""
        <div class="detail-panel">
            <div class="detail-accent-bar"></div>
            
            <div style="margin: 0 20px;">
                <span class="critical-pill">CRITICAL DRIFT</span>
                <span style="font-family:'JetBrains Mono', monospace; font-size:10px; color:#869397; margin-left:10px;">{selected_row['timestamp'][:19]}Z</span>
            </div>
            
            <div class="detail-title">{selected_row['resource_id']}</div>
            <div class="detail-sub">{selected_row['event_type']}</div>
            
            <div class="section-heading">THREAT CONTEXT & BUSINESS RISK</div>
            <div class="threat-text">{context}</div>
            
            <div class="section-heading">CONFIGURATION DIFF</div>
            <div class="json-block">
{formatted_json}
            </div>
            
            <div class="btn-row">
                <button class="btn-ignore">IGNORE (7 DAYS)</button>
                <button class="btn-remediate">AUTO-REMEDIATE</button>
            </div>
        </div>
        """, unsafe_allow_html=True)
else:
    st.info("No active incidents match the current filters.")