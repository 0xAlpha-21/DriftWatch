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

# NEW: Database connection helper defined here
def get_db_connection():
    conn = sqlite3.connect(db_manager.DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

@app.get("/api/metrics")
def get_metrics():
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Get Monitored Assets (from the new table populated by scanner.py)
    cursor.execute("SELECT monitored_assets FROM metrics ORDER BY id DESC LIMIT 1")
    assets_row = cursor.fetchone()
    monitored_assets = assets_row['monitored_assets'] if assets_row else 0

    # 2. Get Active Drifts (Total number of incidents)
    cursor.execute("SELECT COUNT(*) as count FROM incidents")
    active_drifts = cursor.fetchone()['count']

    # 3. Get Critical Risks (Filtering by the highest severity event types)
    cursor.execute("""
        SELECT COUNT(*) as count FROM incidents 
        WHERE event_type IN ('EXPOSED_RDP', 'FULL_ADMIN_PRIVILEGES')
    """)
    critical_risks = cursor.fetchone()['count']

    # 4. Get Privacy Violations (Filtering by data exposure risks)
    cursor.execute("""
        SELECT COUNT(*) as count FROM incidents 
        WHERE event_type = 'PUBLIC_BUCKET_EXPOSED'
    """)
    privacy_violations = cursor.fetchone()['count']

    conn.close()

    return {
        "monitored_assets": monitored_assets,
        "active_drifts": active_drifts,
        "critical_risks": critical_risks,
        "privacy_violations": privacy_violations
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

# from fastapi import FastAPI
# from fastapi.middleware.cors import CORSMiddleware
# import sqlite3
# import pandas as pd
# import db_manager
# import scanner  # Imports scanner module for on-demand execution

# app = FastAPI(title="DriftWatch API")

# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["*"],
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )

# # @app.get("/api/metrics")
# # def get_metrics():
# #     conn = sqlite3.connect(db_manager.DB_NAME)
# #     try:
# #         snaps = pd.read_sql_query("SELECT id FROM snapshots", conn)
# #     except Exception:
# #         snaps = pd.DataFrame()

# #     try:
# #         drifts = pd.read_sql_query("SELECT * FROM incidents", conn)
# #     except Exception:
# #         drifts = pd.DataFrame()

# #     conn.close()
    
# #     active_drifts_count = len(drifts)
# #     critical_count = 0
# #     privacy_count = 0

# #     if not drifts.empty and 'cis_control' in drifts.columns:
# #         critical_count = len(drifts[drifts['cis_control'].fillna('').str.contains('CIS 5.2|CIS 5.3|CIS 1.16', regex=True)])
# #     if not drifts.empty and 'gdpr_control' in drifts.columns:
# #         privacy_count = len(drifts[drifts['gdpr_control'].fillna('').str.contains('GDPR|DPDPA', regex=True)])

# #     return {
# #         "monitored_assets": len(snaps) if not snaps.empty else 0,
# #         "active_drifts": active_drifts_count,
# #         "critical_risks": critical_count,
# #         "privacy_violations": privacy_count
# #     }

# @app.get("/api/metrics")
# def get_metrics():
#     conn = get_db_connection()
#     cursor = conn.cursor()

#     # 1. Get Monitored Assets (from the new table populated by scanner.py)
#     cursor.execute("SELECT monitored_assets FROM metrics ORDER BY id DESC LIMIT 1")
#     assets_row = cursor.fetchone()
#     monitored_assets = assets_row['monitored_assets'] if assets_row else 0

#     # 2. Get Active Drifts (Total number of incidents)
#     cursor.execute("SELECT COUNT(*) as count FROM incidents")
#     active_drifts = cursor.fetchone()['count']

#     # 3. Get Critical Risks (Filtering by the highest severity event types)
#     cursor.execute("""
#         SELECT COUNT(*) as count FROM incidents 
#         WHERE event_type IN ('EXPOSED_RDP', 'FULL_ADMIN_PRIVILEGES')
#     """)
#     critical_risks = cursor.fetchone()['count']

#     # 4. Get Privacy Violations (Filtering by data exposure risks)
#     cursor.execute("""
#         SELECT COUNT(*) as count FROM incidents 
#         WHERE event_type = 'PUBLIC_BUCKET_EXPOSED'
#     """)
#     privacy_violations = cursor.fetchone()['count']

#     conn.close()

#     return {
#         "monitored_assets": monitored_assets,
#         "active_drifts": active_drifts,
#         "critical_risks": critical_risks,
#         "privacy_violations": privacy_violations
#     }

# @app.get("/api/incidents")
# def get_incidents():
#     conn = sqlite3.connect(db_manager.DB_NAME)
#     try:
#         df = pd.read_sql_query("SELECT * FROM incidents ORDER BY id DESC", conn)
#         df = df.fillna("")
#         drifts = df.to_dict(orient="records")
#     except Exception:
#         drifts = []
#     conn.close()
#     return drifts

# @app.post("/api/scan")
# def trigger_scan():
#     try:
#         scanner.scan_aws_environment()
#         return {"status": "success", "message": "AWS Scan completed successfully"}
#     except Exception as e:
#         return {"status": "error", "message": str(e)}

# @app.get("/api/frameworks")
# def get_frameworks():
#     conn = sqlite3.connect(db_manager.DB_NAME)
#     try:
#         df = pd.read_sql_query("SELECT * FROM compliance_controls", conn)
#         df = df.fillna("")
#         controls = df.to_dict(orient="records")
#     except Exception:
#         controls = []
#     conn.close()
#     return controls