from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import sqlite3
import pandas as pd
import db_manager
import scanner  # Imports scanner module for on-demand execution

app = FastAPI(title="DriftWatch API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/metrics")
def get_metrics():
    conn = sqlite3.connect(db_manager.DB_NAME)
    try:
        snaps = pd.read_sql_query("SELECT id FROM snapshots", conn)
    except Exception:
        snaps = pd.DataFrame()

    try:
        drifts = pd.read_sql_query("SELECT * FROM incidents", conn)
    except Exception:
        drifts = pd.DataFrame()

    conn.close()
    
    active_drifts_count = len(drifts)
    critical_count = 0
    privacy_count = 0

    if not drifts.empty and 'cis_control' in drifts.columns:
        critical_count = len(drifts[drifts['cis_control'].fillna('').str.contains('CIS 5.2|CIS 5.3|CIS 1.16', regex=True)])
    if not drifts.empty and 'gdpr_control' in drifts.columns:
        privacy_count = len(drifts[drifts['gdpr_control'].fillna('').str.contains('GDPR|DPDPA', regex=True)])

    return {
        "monitored_assets": len(snaps) if not snaps.empty else 0,
        "active_drifts": active_drifts_count,
        "critical_risks": critical_count,
        "privacy_violations": privacy_count
    }

@app.get("/api/incidents")
def get_incidents():
    conn = sqlite3.connect(db_manager.DB_NAME)
    try:
        df = pd.read_sql_query("SELECT * FROM incidents ORDER BY id DESC", conn)
        df = df.fillna("")
        drifts = df.to_dict(orient="records")
    except Exception:
        drifts = []
    conn.close()
    return drifts

@app.post("/api/scan")
def trigger_scan():
    try:
        scanner.scan_aws_environment()
        return {"status": "success", "message": "AWS Scan completed successfully"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.get("/api/frameworks")
def get_frameworks():
    conn = sqlite3.connect(db_manager.DB_NAME)
    try:
        df = pd.read_sql_query("SELECT * FROM compliance_controls", conn)
        df = df.fillna("")
        controls = df.to_dict(orient="records")
    except Exception:
        controls = []
    conn.close()
    return controls