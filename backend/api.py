from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import sqlite3
import pandas as pd
import db_manager

app = FastAPI(title="DriftWatch API")

# Allow your React app (running on localhost:5173) to talk to this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["*"],
)

@app.get("/api/metrics")
def get_metrics():
    conn = sqlite3.connect(db_manager.DB_NAME)
    snaps = pd.read_sql_query("SELECT id FROM snapshots", conn)
    drifts = pd.read_sql_query("SELECT * FROM drift_logs", conn)
    conn.close()
    
    # Calculate metrics to send to React
    return {
        "monitored_assets": len(snaps),
        "active_drifts": len(drifts),
        "critical_risks": len(drifts[drifts['cis_control'].str.contains('CIS 5.2|CIS 5.1')]),
        "privacy_violations": len(drifts[drifts['gdpr_control'].str.contains('GDPR')])
    }

@app.get("/api/incidents")
def get_incidents():
    conn = sqlite3.connect(db_manager.DB_NAME)
    
    # Fetch data into a DataFrame
    df = pd.read_sql_query("SELECT * FROM drift_logs ORDER BY id DESC", conn)
    
    # FIX: Replace NaN values (unsupported by JSON) with empty strings
    df = df.fillna("")
    
    # Convert to a list of dictionaries for JSON transmission
    drifts = df.to_dict(orient="records")
    
    conn.close()
    return drifts