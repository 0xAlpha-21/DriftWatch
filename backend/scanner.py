import boto3
import json
import sqlite3
from datetime import datetime

DB_PATH = 'driftwatch.db'
REGION = 'us-east-1'

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def record_incident(resource_id, event_type, details, trigger, cis="", iso="", gdpr="", dpdpa=""):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Avoid duplicate active alerts for the same resource & event
    cursor.execute(
        "SELECT id FROM incidents WHERE resource_id = ? AND event_type = ?", 
        (resource_id, event_type)
    )
    existing = cursor.fetchone()
    
    timestamp = datetime.utcnow().isoformat() + "Z"
    
    if not existing:
        cursor.execute('''
            INSERT INTO incidents (
                timestamp, resource_id, event_type, details, 
                violation_trigger, cis_control, iso_control, gdpr_control, dpdpa_control
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (timestamp, resource_id, event_type, json.dumps(details), trigger, cis, iso, gdpr, dpdpa))
        print(f"  [+] DRIFT DETECTED: {resource_id} | Event: {event_type}")
    else:
        print(f"  [-] Alert already exists for {resource_id}")

    conn.commit()
    conn.close()

def scan_aws_environment():
    print("==========================================")
    print("   DRIFTWATCH ENGINE: ACTIVE AWS SCAN")
    print("==========================================")

    # 1. SCAN SECURITY GROUPS
    print("\n[*] Auditing Security Groups...")
    ec2 = boto3.client('ec2', region_name=REGION)
    try:
        sgs = ec2.describe_security_groups()['SecurityGroups']
        for sg in sgs:
            sg_id = sg['GroupId']
            for rule in sg.get('IpPermissions', []):
                from_port = rule.get('FromPort')
                to_port = rule.get('ToPort')
                ip_ranges = [r.get('CidrIp') for r in rule.get('IpRanges', [])]

                if '0.0.0.0/0' in ip_ranges:
                    if from_port == 22 or to_port == 22:
                        record_incident(
                            resource_id=sg_id,
                            event_type="RULES_MODIFIED",
                            details={"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIp": "0.0.0.0/0"},
                            trigger="SSH Port 22 open publicly to 0.0.0.0/0",
                            cis="CIS 0.1", iso="A.8.20", gdpr="Art. 32(1)(b)", dpdpa="Sec. 8(5)"
                        )
                    elif from_port == 3389 or to_port == 3389:
                        record_incident(
                            resource_id=sg_id,
                            event_type="EXPOSED_RDP",
                            details={"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389, "CidrIp": "0.0.0.0/0"},
                            trigger="RDP Port 3389 open publicly to 0.0.0.0/0",
                            cis="CIS 0.2", iso="A.8.20", gdpr="Art. 32(1)(b)", dpdpa="Sec. 8(5)"
                        )
    except Exception as e:
        print(f"  [!] SG Scan Error: {e}")

    # 2. SCAN S3 BUCKETS
    print("\n[*] Auditing S3 Buckets...")
    s3 = boto3.client('s3', region_name=REGION)
    try:
        buckets = s3.list_buckets().get('Buckets', [])
        for b in buckets:
            b_name = b['Name']
            if "driftwatch-exposed-data" in b_name:
                # Check Public Access Block
                try:
                    pab = s3.get_public_access_block(Bucket=b_name)
                    config = pab['PublicAccessBlockConfiguration']
                    is_public = not (config.get('BlockPublicAcls') and config.get('RestrictPublicBuckets'))
                except:
                    is_public = True # If block doesn't exist, it's public

                if is_public:
                    record_incident(
                        resource_id=b_name,
                        event_type="PUBLIC_BUCKET_EXPOSED",
                        details={"Bucket": b_name, "PublicAccessBlock": "DISABLED"},
                        trigger="S3 Bucket public access block is disabled",
                        cis="CIS 2.1.5", iso="A.8.12", gdpr="Art. 32(1)(a)", dpdpa="Sec. 8(4)"
                    )
    except Exception as e:
        print(f"  [!] S3 Scan Error: {e}")

    # 3. SCAN IAM POLICIES
    print("\n[*] Auditing IAM Policies...")
    iam = boto3.client('iam', region_name=REGION)
    try:
        policies = iam.list_policies(Scope='Local').get('Policies', [])
        for p in policies:
            if "sadcloud-overly-permissive" in p['PolicyName']:
                record_incident(
                    resource_id=p['PolicyName'],
                    event_type="FULL_ADMIN_PRIVILEGES",
                    details={"PolicyArn": p['Arn'], "Action": "*", "Resource": "*"},
                    trigger="IAM Policy allows full wildcard '*:*' permissions",
                    cis="CIS 1.16", iso="A.8.2", gdpr="Art. 25(2)", dpdpa="Sec. 8(5)"
                )
    except Exception as e:
        print(f"  [!] IAM Scan Error: {e}")

    print("\n[SUCCESS] AWS Posture Audit Complete.")

if __name__ == "__main__":
    scan_aws_environment()





# v3 above, with multiple cloud resources
# v2 below
# import boto3
# import sqlite3
# import json
# from datetime import datetime, timezone

# def scan_aws_environment():
#     print("[*] Initiating AWS Security Group scan...")
    
#     # boto3 automatically uses the credentials you set with 'aws configure'
#     try:
#         ec2 = boto3.client('ec2', region_name='us-east-1')
#         response = ec2.describe_security_groups()
#     except Exception as e:
#         print(f"[!] Failed to connect to AWS: {e}")
#         return

#     vulnerable_sgs = []

#     # Analyze the AWS data for our intentional drift
#     for sg in response.get('SecurityGroups', []):
#         sg_id = sg['GroupId']
        
#         for rule in sg.get('IpPermissions', []):
#             if rule.get('FromPort') == 22 and rule.get('ToPort') == 22:
#                 for ip_range in rule.get('IpRanges', []):
#                     if ip_range.get('CidrIp') == '0.0.0.0/0':
#                         print(f"[!] Critical Drift Detected in {sg_id}: SSH open to the world.")
#                         vulnerable_sgs.append({
#                             'resource_id': sg_id,
#                             'details': json.dumps(rule)
#                         })
    
#     # Write findings to the database
#     if vulnerable_sgs:
#         try:
#             conn = sqlite3.connect('driftwatch.db')
#             cursor = conn.cursor()
            
#             for vuln in vulnerable_sgs:
#                 timestamp = datetime.now(timezone.utc).isoformat()
#                 cursor.execute('''
#                     INSERT INTO drift_logs (timestamp, resource_id, event_type, details, cis_control, gdpr_control)
#                     VALUES (?, ?, ?, ?, ?, ?)
#                 ''', (timestamp, vuln['resource_id'], 'RULES_MODIFIED', vuln['details'], 'CIS 5.2 - Ensure no security groups allow ingress from 0.0.0.0/0 to port 22', 'GDPR Art. 32 - Unauthorized access risk to PII data stores'))
            
#             conn.commit()
#             conn.close()
#             print(f"[*] Successfully logged {len(vulnerable_sgs)} active incidents to the database.")
#         except Exception as e:
#             print(f"[!] Database error: {e}")
#     else:
#         print("[*] No vulnerabilities detected. Infrastructure matches secure baseline.")

# if __name__ == "__main__":
#     scan_aws_environment()



# import json
# import sqlite3
# from datetime import datetime, timezone
# import backend.db_manager as db_manager

# # Mock AWS Security Group configurations
# # # MOCK DATA 1: SECURE BASELINE
# # MOCK_SECURITY_GROUPS = [
# #     {
# #         "GroupId": "sg-0a1b2c3d4e5f67890",
# #         "GroupName": "web-server-sg",
# #         "Description": "Allow HTTP and HTTPS traffic",
# #         "IpPermissions": [
# #             {
# #                 "IpProtocol": "tcp", "FromPort": 80, "ToPort": 80,
# #                 "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
# #             },
# #             {
# #                 "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
# #                 "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
# #             }
# #         ]
# #     },
# #     {
# #         "GroupId": "sg-0987654321fedcba0",
# #         "GroupName": "db-server-sg",
# #         "Description": "Database access restricted to VPC internal subnet",
# #         "IpPermissions": [
# #             {
# #                 "IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432,
# #                 "IpRanges": [{"CidrIp": "10.0.0.0/16"}]  # Secure: Internal VPC only
# #             }
# #         ]
# #     }
# # ]

# # MOCK DATA 2: INSECURE DRIFT
# MOCK_SECURITY_GROUPS = [
#     {
#         "GroupId": "sg-0a1b2c3d4e5f67890",
#         "GroupName": "web-server-sg",
#         "Description": "Allow HTTP and HTTPS traffic",
#         "IpPermissions": [
#             {
#                 "IpProtocol": "tcp", "FromPort": 80, "ToPort": 80,
#                 "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
#             },
#             {
#                 "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
#                 "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
#             },
#             # 🚨 DRIFT 1: SSH (22) exposed to the entire internet
#             {
#                 "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
#                 "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
#             }
#         ]
#     },
#     {
#         "GroupId": "sg-0987654321fedcba0",
#         "GroupName": "db-server-sg",
#         "Description": "Database access restricted to VPC internal subnet",
#         "IpPermissions": [
#             {
#                 "IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432,
#                 "IpRanges": [{"CidrIp": "10.0.0.0/16"}]
#             },
#             # 🚨 DRIFT 2: MySQL Database (3306) exposed to the entire internet
#             {
#                 "IpProtocol": "tcp", "FromPort": 3306, "ToPort": 3306,
#                 "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
#             }
#         ]
#     }
# ]

# def fetch_security_groups(use_mock=True):
#     """
#     Fetches Security Group configurations.
#     Uses mock data by default until live AWS boto3 credentials are configured.
#     """
#     if use_mock:
#         print("ℹ️ Using mock AWS Security Group snapshot data...")
#         return MOCK_SECURITY_GROUPS
#     else:
#         # Placeholder for live boto3 call once AWS account is active
#         # import boto3
#         # ec2 = boto3.client('ec2')
#         # return ec2.describe_security_groups()['SecurityGroups']
#         pass

# def save_snapshot(resource_type, state_data):
#     """Saves a JSON-encoded configuration state snapshot to driftwatch.db."""
#     conn = sqlite3.connect(db_manager.DB_NAME)
#     cursor = conn.cursor()
    
#     timestamp = datetime.now(timezone.utc).isoformat()
#     json_data = json.dumps(state_data, indent=2)
    
#     cursor.execute('''
#         INSERT INTO snapshots (timestamp, resource_type, state_data)
#         VALUES (?, ?, ?)
#     ''', (timestamp, resource_type, json_data))
    
#     conn.commit()
#     conn.close()
#     print(f" [{timestamp}] Snapshot for '{resource_type}' recorded successfully.")

# def run_scan():
#     """Runs the full snapshot scan routine."""
#     print("Starting AWS Configuration Scan...")
#     sg_data = fetch_security_groups(use_mock=True)
#     save_snapshot("AWS::EC2::SecurityGroup", sg_data)
#     print("Scan routine finished.")

# if __name__ == "__main__":
#     run_scan()