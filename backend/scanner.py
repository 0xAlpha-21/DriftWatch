import boto3
import sqlite3
import json
from datetime import datetime, timezone

def scan_aws_environment():
    print("[*] Initiating AWS Security Group scan...")
    
    # boto3 automatically uses the credentials you set with 'aws configure'
    try:
        ec2 = boto3.client('ec2', region_name='us-east-1')
        response = ec2.describe_security_groups()
    except Exception as e:
        print(f"[!] Failed to connect to AWS: {e}")
        return

    vulnerable_sgs = []

    # Analyze the AWS data for our intentional drift
    for sg in response.get('SecurityGroups', []):
        sg_id = sg['GroupId']
        
        for rule in sg.get('IpPermissions', []):
            if rule.get('FromPort') == 22 and rule.get('ToPort') == 22:
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        print(f"[!] Critical Drift Detected in {sg_id}: SSH open to the world.")
                        vulnerable_sgs.append({
                            'resource_id': sg_id,
                            'details': json.dumps(rule)
                        })
    
    # Write findings to the database
    if vulnerable_sgs:
        try:
            conn = sqlite3.connect('driftwatch.db')
            cursor = conn.cursor()
            
            for vuln in vulnerable_sgs:
                timestamp = datetime.now(timezone.utc).isoformat()
                cursor.execute('''
                    INSERT INTO drift_logs (timestamp, resource_id, event_type, details, cis_control, gdpr_control)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (timestamp, vuln['resource_id'], 'RULES_MODIFIED', vuln['details'], 'CIS 5.2 - Ensure no security groups allow ingress from 0.0.0.0/0 to port 22', 'GDPR Art. 32 - Unauthorized access risk to PII data stores'))
            
            conn.commit()
            conn.close()
            print(f"[*] Successfully logged {len(vulnerable_sgs)} active incidents to the database.")
        except Exception as e:
            print(f"[!] Database error: {e}")
    else:
        print("[*] No vulnerabilities detected. Infrastructure matches secure baseline.")

if __name__ == "__main__":
    scan_aws_environment()



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