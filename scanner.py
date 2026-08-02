import json
import sqlite3
from datetime import datetime, timezone
import db_manager

# Mock AWS Security Group configurations
MOCK_SECURITY_GROUPS = [
    {
        "GroupId": "sg-0a1b2c3d4e5f67890",
        "GroupName": "web-server-sg",
        "Description": "Allow HTTP and HTTPS traffic",
        "IpPermissions": [
            {
                "IpProtocol": "tcp",
                "FromPort": 80,
                "ToPort": 80,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            },
            {
                "IpProtocol": "tcp",
                "FromPort": 443,
                "ToPort": 443,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            }
        ]
    },
    {
        "GroupId": "sg-0987654321fedcba0",
        "GroupName": "db-server-sg",
        "Description": "Database access restricted to VPC internal subnet",
        "IpPermissions": [
            {
                "IpProtocol": "tcp",
                "FromPort": 5432,
                "ToPort": 5432,
                "IpRanges": [{"CidrIp": "10.0.0.0/16"}]
            }
        ]
    }
]

def fetch_security_groups(use_mock=True):
    """
    Fetches Security Group configurations.
    Uses mock data by default until live AWS boto3 credentials are configured.
    """
    if use_mock:
        print("ℹ️ Using mock AWS Security Group snapshot data...")
        return MOCK_SECURITY_GROUPS
    else:
        # Placeholder for live boto3 call once AWS account is active
        # import boto3
        # ec2 = boto3.client('ec2')
        # return ec2.describe_security_groups()['SecurityGroups']
        pass

def save_snapshot(resource_type, state_data):
    """Saves a JSON-encoded configuration state snapshot to driftwatch.db."""
    conn = sqlite3.connect(db_manager.DB_NAME)
    cursor = conn.cursor()
    
    timestamp = datetime.now(timezone.utc).isoformat()
    json_data = json.dumps(state_data, indent=2)
    
    cursor.execute('''
        INSERT INTO snapshots (timestamp, resource_type, state_data)
        VALUES (?, ?, ?)
    ''', (timestamp, resource_type, json_data))
    
    conn.commit()
    conn.close()
    print(f" [{timestamp}] Snapshot for '{resource_type}' recorded successfully.")

def run_scan():
    """Runs the full snapshot scan routine."""
    print("Starting AWS Configuration Scan...")
    sg_data = fetch_security_groups(use_mock=True)
    save_snapshot("AWS::EC2::SecurityGroup", sg_data)
    print("Scan routine finished.")

if __name__ == "__main__":
    run_scan()