import sqlite3
import os

# Dynamically resolve absolute path to driftwatch.db in the same directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_NAME = os.path.join(BASE_DIR, 'driftwatch.db')

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # Table 1: Historical drift events (Renamed to 'incidents' to match scanner.py)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            resource_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            details TEXT NOT NULL,
            violation_trigger TEXT NOT NULL,
            cis_control TEXT,
            iso_control TEXT,
            gdpr_control TEXT,
            dpdpa_control TEXT
        )
    ''')

    # Table 2: Compliance Framework Dictionary 
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS compliance_controls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            framework TEXT NOT NULL,
            control_id TEXT NOT NULL,
            description TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            trigger_condition TEXT NOT NULL
        )
    ''')

    # Clear existing compliance controls to prevent duplicates on re-runs
    cursor.execute('DELETE FROM compliance_controls')

    # Seed 40 specific compliance controls with technical trigger mappings
    frameworks = [
        # --- CIS (Center for Internet Security) AWS Foundations ---
        ('CIS', 'CIS 1.2', 'Ensure MFA is enabled for all IAM users', 'High', 'MFA device not configured for user'),
        ('CIS', 'CIS 1.16', 'Ensure IAM policies do not allow full "*:*" admin privileges', 'Critical', 'IAM policy contains Action: "*" and Resource: "*"'),
        ('CIS', 'CIS 2.1.1', 'Ensure all S3 buckets employ encryption-at-rest', 'High', 'S3 ServerSideEncryptionConfiguration is missing or false'),
        ('CIS', 'CIS 2.1.5', 'Ensure S3 Buckets are configured with Block Public Access', 'Critical', 'S3 BlockPublicAcls or IgnorePublicAcls set to False'),
        ('CIS', 'CIS 3.1', 'Ensure CloudTrail is enabled in all regions', 'High', 'CloudTrail status is stopped or deleted'),
        ('CIS', 'CIS 4.1.1', 'Ensure EBS volume encryption is enabled by default', 'High', 'EBS volume Encrypted flag set to False'),
        ('CIS', 'CIS 4.3.3', 'Ensure RDS instances have encryption at rest enabled', 'High', 'RDS StorageEncrypted flag set to False'),
        ('CIS', 'CIS 4.3.4', 'Ensure RDS instances are not publicly accessible', 'Critical', 'RDS PubliclyAccessible flag set to True'),
        ('CIS', 'CIS 5.2', 'Ensure no security groups allow ingress from 0.0.0.0/0 to port 22', 'Critical', 'Inbound SG rule allows 0.0.0.0/0 to Port 22 (SSH)'),
        ('CIS', 'CIS 5.3', 'Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389', 'Critical', 'Inbound SG rule allows 0.0.0.0/0 to Port 3389 (RDP)'),

        # --- ISO/IEC 27001:2022 ---
        ('ISO', 'A.5.15', 'Access control: Restrict broad access rights', 'Critical', 'IAM policy contains Action: "*" and Resource: "*"'),
        ('ISO', 'A.5.17', 'Authentication information: Secure log-on procedures', 'High', 'MFA device not configured for user'),
        ('ISO', 'A.8.11', 'Data masking: Storage encryption for sensitive data (S3)', 'High', 'S3 ServerSideEncryptionConfiguration is missing or false'),
        ('ISO', 'A.8.11', 'Data masking: Storage encryption for sensitive data (EBS)', 'High', 'EBS volume Encrypted flag set to False'),
        ('ISO', 'A.8.11', 'Data masking: Storage encryption for sensitive data (RDS)', 'High', 'RDS StorageEncrypted flag set to False'),
        ('ISO', 'A.8.12', 'Data leakage prevention: S3 public access blocked', 'Critical', 'S3 BlockPublicAcls or IgnorePublicAcls set to False'),
        ('ISO', 'A.8.12', 'Data leakage prevention: RDS public access blocked', 'Critical', 'RDS PubliclyAccessible flag set to True'),
        ('ISO', 'A.8.16', 'Monitoring activities: Event logging active', 'High', 'CloudTrail status is stopped or deleted'),
        ('ISO', 'A.8.20', 'Network security: Secure network architectures (SSH)', 'Critical', 'Inbound SG rule allows 0.0.0.0/0 to Port 22 (SSH)'),
        ('ISO', 'A.8.20', 'Network security: Secure network architectures (RDP)', 'Critical', 'Inbound SG rule allows 0.0.0.0/0 to Port 3389 (RDP)'),

        # --- GDPR (General Data Protection Regulation) ---
        ('GDPR', 'Art. 5(1)(f)', 'Integrity & Confidentiality: Restrict admin privileges', 'Critical', 'IAM policy contains Action: "*" and Resource: "*"'),
        ('GDPR', 'Art. 25', 'Data protection by design: S3 public access blocked', 'Critical', 'S3 BlockPublicAcls or IgnorePublicAcls set to False'),
        ('GDPR', 'Art. 25', 'Data protection by design: RDS public access blocked', 'Critical', 'RDS PubliclyAccessible flag set to True'),
        ('GDPR', 'Art. 32(1)(a)', 'Security of processing: Pseudonymisation and encryption (S3)', 'High', 'S3 ServerSideEncryptionConfiguration is missing or false'),
        ('GDPR', 'Art. 32(1)(a)', 'Security of processing: Pseudonymisation and encryption (EBS)', 'High', 'EBS volume Encrypted flag set to False'),
        ('GDPR', 'Art. 32(1)(a)', 'Security of processing: Pseudonymisation and encryption (RDS)', 'High', 'RDS StorageEncrypted flag set to False'),
        ('GDPR', 'Art. 32(1)(b)', 'Security of processing: Ongoing confidentiality (MFA)', 'High', 'MFA device not configured for user'),
        ('GDPR', 'Art. 32(1)(b)', 'Security of processing: Ongoing confidentiality (SSH)', 'Critical', 'Inbound SG rule allows 0.0.0.0/0 to Port 22 (SSH)'),
        ('GDPR', 'Art. 32(1)(b)', 'Security of processing: Ongoing confidentiality (RDP)', 'Critical', 'Inbound SG rule allows 0.0.0.0/0 to Port 3389 (RDP)'),
        ('GDPR', 'Art. 33', 'Notification of breach: Audit logs enabled', 'High', 'CloudTrail status is stopped or deleted'),

        # --- DPDPA 2023 (Digital Personal Data Protection Act - India) ---
        ('DPDPA', 'Sec. 8(1)', 'Data Fiduciary compliance: Restrict broad admin access', 'Critical', 'IAM policy contains Action: "*" and Resource: "*"'),
        ('DPDPA', 'Sec. 8(1)', 'Data Fiduciary compliance: Multi-factor authentication', 'High', 'MFA device not configured for user'),
        ('DPDPA', 'Sec. 8(4)', 'Appropriate technical measures: S3 public access blocked', 'Critical', 'S3 BlockPublicAcls or IgnorePublicAcls set to False'),
        ('DPDPA', 'Sec. 8(4)', 'Appropriate technical measures: RDS public access blocked', 'Critical', 'RDS PubliclyAccessible flag set to True'),
        ('DPDPA', 'Sec. 8(5)', 'Protect personal data: Prevent breach via network (SSH)', 'Critical', 'Inbound SG rule allows 0.0.0.0/0 to Port 22 (SSH)'),
        ('DPDPA', 'Sec. 8(5)', 'Protect personal data: Prevent breach via network (RDP)', 'Critical', 'Inbound SG rule allows 0.0.0.0/0 to Port 3389 (RDP)'),
        ('DPDPA', 'Sec. 8(5)', 'Protect personal data: Reasonable safeguards (S3 Encryption)', 'High', 'S3 ServerSideEncryptionConfiguration is missing or false'),
        ('DPDPA', 'Sec. 8(5)', 'Protect personal data: Reasonable safeguards (EBS Encryption)', 'High', 'EBS volume Encrypted flag set to False'),
        ('DPDPA', 'Sec. 8(5)', 'Protect personal data: Reasonable safeguards (RDS Encryption)', 'High', 'RDS StorageEncrypted flag set to False'),
        ('DPDPA', 'Sec. 8(6)', 'Personal data breach notification: Audit logs enabled', 'High', 'CloudTrail status is stopped or deleted')
    ]

    cursor.executemany('''
        INSERT INTO compliance_controls (framework, control_id, description, risk_level, trigger_condition)
        VALUES (?, ?, ?, ?, ?)
    ''', frameworks)

    conn.commit()
    conn.close()
    print("[*] Database initialized successfully. 40 Compliance policies and triggers seeded.")

if __name__ == "__main__":
    init_db()