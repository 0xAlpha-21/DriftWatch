import json
import sqlite3
from datetime import datetime, timezone
import backend.db_manager as db_manager

# Expanded Compliance Mapping Reference
COMPLIANCE_MAP = {
    "OPEN_INBOUND_SSH": {
        "cis": "CIS 5.2 - Ensure no security groups allow ingress from 0.0.0.0/0 to port 22",
        "iso": "ISO 27001:2022 A.8.20 - Network Security Control",
        "gdpr": "GDPR Art. 32(1)(b) - Failure to ensure ongoing confidentiality",
        "dpdpa": "DPDPA Sec 8(4) - Failure of reasonable security safeguards"
    },
    "OPEN_INBOUND_DB": {
        "cis": "CIS 5.3 - Ensure strict least privilege configuration",
        "iso": "ISO 27001:2022 A.8.9 - Configuration Management",
        "gdpr": "GDPR Art. 32 - Unauthorized access risk to PII data stores",
        "dpdpa": "DPDPA Sec 8(4) - High risk of personal data breach via direct DB access"
    },
    "OPEN_INBOUND_ALL": {
        "cis": "CIS 5.1 - Ensure no security groups allow ingress from 0.0.0.0/0 to all ports",
        "iso": "ISO 27001:2022 A.8.21 - Security of Network Services",
        "gdpr": "GDPR Art. 25 - Failure of Data Protection by Design and by Default",
        "dpdpa": "DPDPA Sec 8(4) - Complete failure of reasonable security safeguards"
    },
    "GENERIC_DRIFT": {
        "cis": "CIS 5.3 - Review for least privilege",
        "iso": "ISO 27001:2022 A.8.9 - Configuration Management",
        "gdpr": "GDPR Art. 32 - Monitor configuration drift for processing security",
        "dpdpa": "DPDPA Sec 8 - General safeguard review required"
    }
}

def get_latest_two_snapshots(resource_type="AWS::EC2::SecurityGroup"):
    """Retrieves the most recent two snapshots from the database for comparison."""
    conn = sqlite3.connect(db_manager.DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, timestamp, state_data FROM snapshots
        WHERE resource_type = ?
        ORDER BY id DESC LIMIT 2
    ''', (resource_type,))
    
    rows = cursor.fetchall()
    conn.close()
    
    if len(rows) < 2:
        return None, None
    
    current_snapshot = json.loads(rows[0][2])
    previous_snapshot = json.loads(rows[1][2])
    
    return previous_snapshot, current_snapshot

def analyze_compliance_risk(event_type, details):
    """Maps drift findings to CIS, ISO, GDPR, and DPDPA."""
    details_str = str(details).lower()
    
    if "0.0.0.0/0" in details_str and ("22" in details_str or "ssh" in details_str):
        return COMPLIANCE_MAP["OPEN_INBOUND_SSH"]
    # NEW: Catch database ports (RDP, PostgreSQL, MySQL) open to the internet
    elif "0.0.0.0/0" in details_str and any(port in details_str for port in ["3389", "5432", "3306"]):
        return COMPLIANCE_MAP["OPEN_INBOUND_DB"]
    elif "0.0.0.0/0" in details_str and "all" in details_str:
        return COMPLIANCE_MAP["OPEN_INBOUND_ALL"]
    
    return COMPLIANCE_MAP["GENERIC_DRIFT"]

def log_drift(resource_id, event_type, details):
    """Inserts a detected drift event into the drift_logs table with new compliance mappings."""
    conn = sqlite3.connect(db_manager.DB_NAME)
    cursor = conn.cursor()
    
    timestamp = datetime.now(timezone.utc).isoformat()
    compliance = analyze_compliance_risk(event_type, details)
    
    # Updated to bind 8 parameters
    cursor.execute('''
        INSERT INTO drift_logs (timestamp, resource_id, event_type, details, cis_control, iso_control, gdpr_control, dpdpa_control)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (timestamp, resource_id, event_type, json.dumps(details), compliance["cis"], compliance["iso"], compliance["gdpr"], compliance["dpdpa"]))
    
    conn.commit()
    conn.close()
    print(f"🚨 [DRIFT DETECTED] Resource: {resource_id} | Event: {event_type}")


    
def detect_drift():
    """Compares baseline vs current configuration to spot additions, deletions, or updates."""
    previous, current = get_latest_two_snapshots()
    
    if not previous or not current:
        print("ℹ️ Need at least 2 snapshots to perform drift analysis. Run scanner.py again to generate a new snapshot.")
        return 0

    print("🔎 Analyzing configuration drift between consecutive snapshots...")
    drift_count = 0
    
    prev_sgs = {sg["GroupId"]: sg for sg in previous}
    curr_sgs = {sg["GroupId"]: sg for sg in current}
    
    # 1. Check for modified or removed rules in existing Security Groups
    for sg_id, curr_sg in curr_sgs.items():
        if sg_id in prev_sgs:
            prev_sg = prev_sgs[sg_id]
            if curr_sg != prev_sg:
                drift_count += 1
                diff_details = {
                    "previous_rules": prev_sg.get("IpPermissions", []),
                    "current_rules": curr_sg.get("IpPermissions", [])
                }
                log_drift(sg_id, "RULES_MODIFIED", diff_details)
        else:
            # 2. Check for newly added Security Groups
            drift_count += 1
            log_drift(sg_id, "SECURITY_GROUP_CREATED", curr_sg)
            
    # 3. Check for deleted Security Groups
    for sg_id, prev_sg in prev_sgs.items():
        if sg_id not in curr_sgs:
            drift_count += 1
            log_drift(sg_id, "SECURITY_GROUP_DELETED", prev_sg)
            
    if drift_count == 0:
        print("✅ No configuration drift detected. State is synchronized with baseline.")
        
    return drift_count

if __name__ == "__main__":
    detect_drift()