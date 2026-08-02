import sqlite3
import json
import pandas as pd
import streamlit as st
import db_manager

# Page Configuration
st.set_page_config(
    page_title="DriftWatch - AWS Security Group Drift Monitor",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ DriftWatch: Cloud Security Group Monitor")
st.caption("Real-time AWS Security Group Drift Detection & Compliance Engine")

# Helper Functions
def load_drift_logs():
    conn = sqlite3.connect(db_manager.DB_NAME)
    df = pd.read_sql_query("SELECT * FROM drift_logs ORDER BY id DESC", conn)
    conn.close()
    return df

def load_snapshots():
    conn = sqlite3.connect(db_manager.DB_NAME)
    df = pd.read_sql_query("SELECT * FROM snapshots ORDER BY id DESC", conn)
    conn.close()
    return df

# Data Loading
drift_df = load_drift_logs()
snapshot_df = load_snapshots()

# --- Top Metrics Row ---
col1, col2, col3 = st.columns(3)
with col1:
    st.metric("Total Snapshots Captured", len(snapshot_df))
with col2:
    st.metric("Total Drift Events Logged", len(drift_df), delta_color="inverse")
with col3:
    critical_drifts = len(drift_df[drift_df['cis_control'].str.contains('CIS 5.2|CIS 5.1', na=False)]) if not drift_df.empty else 0
    st.metric("Critical Security Violations", critical_drifts)

st.divider()

# --- Main Layout Tabs ---
tab1, tab2 = st.tabs(["🚨 Detected Drift Events", "📸 Raw Snapshot History"])

with tab1:
    st.subheader("Historical Drift Findings & Compliance Mapping")
    if drift_df.empty:
        st.success("No drift events logged yet. Run scanner and drift engine to detect changes!")
    else:
        for idx, row in drift_df.iterrows():
            with st.expander(f"🚨 [{row['timestamp'][:19]}] Resource: {row['resource_id']} - {row['event_type']}"):
                col_a, col_b = st.columns(2)
                with col_a:
                    st.markdown("**Compliance Violation Mapping:**")
                    st.error(f"**CIS:** {row['cis_control']}")
                    st.warning(f"**ISO 27001:** {row['iso_control']}")
                with col_b:
                    st.markdown("**Drift Details:**")
                    try:
                        st.json(json.loads(row['details']))
                    except Exception:
                        st.text(row['details'])

with tab2:
    st.subheader("Captured Configuration Snapshots")
    if snapshot_df.empty:
        st.info("No snapshots recorded yet.")
    else:
        for idx, row in snapshot_df.iterrows():
            with st.expander(f"📸 Snapshot #{row['id']} - {row['timestamp'][:19]} ({row['resource_type']})"):
                st.json(json.loads(row['state_data']))