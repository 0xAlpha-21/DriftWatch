#version 2
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
    # S3 Storage Drifts
    "PUBLIC_BUCKET_EXPOSED": {
        "cis": "CIS 2.1.5 - Ensure that S3 Buckets are configured with 'Block public access'",
        "iso": "ISO 27001:2022 A.8.3 - Information Access Restriction",
        "gdpr": "GDPR Art. 32 - Unauthorized exposure of data sets",
        "dpdpa": "DPDPA Sec 8 - Failure to implement reasonable security practices for data"
    },
    
    # IAM Privilege Drifts
    "FULL_ADMIN_PRIVILEGES": {
        "cis": "CIS 1.16 - Ensure IAM policies that allow full '*:*' administrative privileges are not created",
        "iso": "ISO 27001:2022 A.8.2 - Privileged Access Rights",
        "gdpr": "GDPR Art. 25(2) - Excessive processing privileges",
        "dpdpa": "DPDPA Sec 8(5) - Inadequate access controls to personal data"
    },
    
    # Lambda / Serverless Drifts
    "HARDCODED_SECRETS": {
        "cis": "CIS 1.1 - Maintain secure secret management and avoid hardcoded keys",
        "iso": "ISO 27001:2022 A.8.2.1 - Management of secret authentication information",
        "gdpr": "GDPR Art. 32(1)(a) - Lack of encryption/pseudonymization of sensitive tokens",
        "dpdpa": "DPDPA Sec 8(4) - Unprotected credential exposure"
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
    # Fast path for direct event_type matches from scanner.py
    if event_type in COMPLIANCE_MAP:
        return COMPLIANCE_MAP[event_type]

    # Deep inspection for complex network rules
    details_str = str(details).lower()
    
    if "0.0.0.0/0" in details_str and ("22" in details_str or "ssh" in details_str):
        return COMPLIANCE_MAP["OPEN_INBOUND_SSH"]
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
        print("ℹ️ Need at least 2 snapshots to perform drift analysis.")
        return []

    print("🔎 Analyzing configuration drift between consecutive snapshots...")
    detected_drifts = []
    
    prev_sgs = {sg["GroupId"]: sg for sg in previous}
    curr_sgs = {sg["GroupId"]: sg for sg in current}
    
    # 1. Check for modified or removed rules
    for sg_id, curr_sg in curr_sgs.items():
        if sg_id in prev_sgs:
            prev_sg = prev_sgs[sg_id]
            if curr_sg != prev_sg:
                diff_details = {
                    "previous_rules": prev_sg.get("IpPermissions", []),
                    "current_rules": curr_sg.get("IpPermissions", [])
                }
                log_drift(sg_id, "RULES_MODIFIED", diff_details)
                detected_drifts.append({
                    "resource_id": sg_id,
                    "event_type": "RULES_MODIFIED",
                    "details": diff_details,
                    "compliance": analyze_compliance_risk("RULES_MODIFIED", diff_details)
                })
        else:
            # 2. Check for newly added Security Groups
            log_drift(sg_id, "SECURITY_GROUP_CREATED", curr_sg)
            
    return detected_drifts

def generate_compliance_report_data():
    """
    Packages the live environment state and active drifts into a structured payload
    for the PDF generation engine (Auditor and Executive targets).
    """
    drifts = detect_drift()
    
    # Calculate posture score (simple heuristic: 100 - (drifts * 15), min 0)
    posture_score = max(0, 100 - (len(drifts) * 15))
    
    report_data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_drifts": len(drifts),
        "posture_score": posture_score,
        "environment_status": "COMPLIANT" if len(drifts) == 0 else "VULNERABLE",
        "detailed_findings": drifts,
        "executive_summary": {
            "critical_risks": sum(1 for d in drifts if "0.0.0.0/0" in str(d['details'])),
            "regulatory_impact": ["CIS", "ISO 27001", "GDPR", "DPDPA"] if drifts else []
        }
    }
    return report_data

if __name__ == "__main__":
    detect_drift()


# version 1 : 
# import json
# import sqlite3
# from datetime import datetime, timezone
# import backend.db_manager as db_manager

# # Expanded Compliance Mapping Reference
# COMPLIANCE_MAP = {
#     "OPEN_INBOUND_SSH": {
#         "cis": "CIS 5.2 - Ensure no security groups allow ingress from 0.0.0.0/0 to port 22",
#         "iso": "ISO 27001:2022 A.8.20 - Network Security Control",
#         "gdpr": "GDPR Art. 32(1)(b) - Failure to ensure ongoing confidentiality",
#         "dpdpa": "DPDPA Sec 8(4) - Failure of reasonable security safeguards"
#     },
#     "OPEN_INBOUND_DB": {
#         "cis": "CIS 5.3 - Ensure strict least privilege configuration",
#         "iso": "ISO 27001:2022 A.8.9 - Configuration Management",
#         "gdpr": "GDPR Art. 32 - Unauthorized access risk to PII data stores",
#         "dpdpa": "DPDPA Sec 8(4) - High risk of personal data breach via direct DB access"
#     },
#     "OPEN_INBOUND_ALL": {
#         "cis": "CIS 5.1 - Ensure no security groups allow ingress from 0.0.0.0/0 to all ports",
#         "iso": "ISO 27001:2022 A.8.21 - Security of Network Services",
#         "gdpr": "GDPR Art. 25 - Failure of Data Protection by Design and by Default",
#         "dpdpa": "DPDPA Sec 8(4) - Complete failure of reasonable security safeguards"
#     },
#     "GENERIC_DRIFT": {
#         "cis": "CIS 5.3 - Review for least privilege",
#         "iso": "ISO 27001:2022 A.8.9 - Configuration Management",
#         "gdpr": "GDPR Art. 32 - Monitor configuration drift for processing security",
#         "dpdpa": "DPDPA Sec 8 - General safeguard review required"
#     }
# }

# def get_latest_two_snapshots(resource_type="AWS::EC2::SecurityGroup"):
#     """Retrieves the most recent two snapshots from the database for comparison."""
#     conn = sqlite3.connect(db_manager.DB_NAME)
#     cursor = conn.cursor()
    
#     cursor.execute('''
#         SELECT id, timestamp, state_data FROM snapshots
#         WHERE resource_type = ?
#         ORDER BY id DESC LIMIT 2
#     ''', (resource_type,))
    
#     rows = cursor.fetchall()
#     conn.close()
    
#     if len(rows) < 2:
#         return None, None
    
#     current_snapshot = json.loads(rows[0][2])
#     previous_snapshot = json.loads(rows[1][2])
    
#     return previous_snapshot, current_snapshot

# def analyze_compliance_risk(event_type, details):
#     """Maps drift findings to CIS, ISO, GDPR, and DPDPA."""
#     details_str = str(details).lower()
    
#     if "0.0.0.0/0" in details_str and ("22" in details_str or "ssh" in details_str):
#         return COMPLIANCE_MAP["OPEN_INBOUND_SSH"]
#     # NEW: Catch database ports (RDP, PostgreSQL, MySQL) open to the internet
#     elif "0.0.0.0/0" in details_str and any(port in details_str for port in ["3389", "5432", "3306"]):
#         return COMPLIANCE_MAP["OPEN_INBOUND_DB"]
#     elif "0.0.0.0/0" in details_str and "all" in details_str:
#         return COMPLIANCE_MAP["OPEN_INBOUND_ALL"]
    
#     return COMPLIANCE_MAP["GENERIC_DRIFT"]

# def log_drift(resource_id, event_type, details):
#     """Inserts a detected drift event into the drift_logs table with new compliance mappings."""
#     conn = sqlite3.connect(db_manager.DB_NAME)
#     cursor = conn.cursor()
    
#     timestamp = datetime.now(timezone.utc).isoformat()
#     compliance = analyze_compliance_risk(event_type, details)
    
#     # Updated to bind 8 parameters
#     cursor.execute('''
#         INSERT INTO drift_logs (timestamp, resource_id, event_type, details, cis_control, iso_control, gdpr_control, dpdpa_control)
#         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
#     ''', (timestamp, resource_id, event_type, json.dumps(details), compliance["cis"], compliance["iso"], compliance["gdpr"], compliance["dpdpa"]))
    
#     conn.commit()
#     conn.close()
#     print(f"🚨 [DRIFT DETECTED] Resource: {resource_id} | Event: {event_type}")


    
# def detect_drift():
#     """Compares baseline vs current configuration to spot additions, deletions, or updates."""
#     previous, current = get_latest_two_snapshots()
    
#     if not previous or not current:
#         print("ℹ️ Need at least 2 snapshots to perform drift analysis. Run scanner.py again to generate a new snapshot.")
#         return 0

#     print("🔎 Analyzing configuration drift between consecutive snapshots...")
#     drift_count = 0
    
#     prev_sgs = {sg["GroupId"]: sg for sg in previous}
#     curr_sgs = {sg["GroupId"]: sg for sg in current}
    
#     # 1. Check for modified or removed rules in existing Security Groups
#     for sg_id, curr_sg in curr_sgs.items():
#         if sg_id in prev_sgs:
#             prev_sg = prev_sgs[sg_id]
#             if curr_sg != prev_sg:
#                 drift_count += 1
#                 diff_details = {
#                     "previous_rules": prev_sg.get("IpPermissions", []),
#                     "current_rules": curr_sg.get("IpPermissions", [])
#                 }
#                 log_drift(sg_id, "RULES_MODIFIED", diff_details)
#         else:
#             # 2. Check for newly added Security Groups
#             drift_count += 1
#             log_drift(sg_id, "SECURITY_GROUP_CREATED", curr_sg)
            
#     # 3. Check for deleted Security Groups
#     for sg_id, prev_sg in prev_sgs.items():
#         if sg_id not in curr_sgs:
#             drift_count += 1
#             log_drift(sg_id, "SECURITY_GROUP_DELETED", prev_sg)
            
#     if drift_count == 0:
#         print(" No configuration drift detected. State is synchronized with baseline.")
        
#     return drift_count

# if __name__ == "__main__":
#     detect_drift()