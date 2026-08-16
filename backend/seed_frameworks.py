import sqlite3

DB_PATH = 'driftwatch.db'

def seed_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # 1. Create the table if it doesn't exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS frameworks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            framework TEXT,
            control_id TEXT,
            description TEXT,
            trigger TEXT,
            severity TEXT
        )
    ''')
    
    # 2. Clear any accidental empty rows to prevent duplicates
    cursor.execute('DELETE FROM frameworks')
    
    # 3. The complete 40-rule framework matrix
    rules = [
        # ==========================================
        # CIS FOUNDATIONS (10 Controls)
        # ==========================================
        ("CIS", "CIS 1.2", "Ensure MFA is enabled for all IAM users", "MFA device not configured for user", "HIGH"),
        ("CIS", "CIS 1.16", "Ensure IAM policies do not allow full '*:*' admin privileges", 'IAM policy contains Action: "*" and Resource: "*"', "CRITICAL"),
        ("CIS", "CIS 2.1.1", "Ensure all S3 buckets employ encryption-at-rest", "S3 ServerSideEncryptionConfiguration is missing or false", "HIGH"),
        ("CIS", "CIS 2.1.5", "Ensure S3 Buckets are configured with Block Public Access", "S3 BlockPublicAcls or IgnorePublicAcls set to False", "CRITICAL"),
        ("CIS", "CIS 3.1", "Ensure CloudTrail is enabled in all regions", "CloudTrail status is stopped or deleted", "HIGH"),
        ("CIS", "CIS 4.1.1", "Ensure EBS volume encryption is enabled by default", "EBS volume Encrypted flag set to False", "HIGH"),
        ("CIS", "CIS 4.3.3", "Ensure RDS instances have encryption at rest enabled", "RDS StorageEncrypted flag set to False", "HIGH"),
        ("CIS", "CIS 4.3.4", "Ensure RDS instances are not publicly accessible", "RDS PubliclyAccessible flag set to True", "CRITICAL"),
        ("CIS", "CIS 5.2", "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22", "Inbound SG rule allows 0.0.0.0/0 to Port 22 (SSH)", "CRITICAL"),
        ("CIS", "CIS 5.3", "Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389", "Inbound SG rule allows 0.0.0.0/0 to Port 3389 (RDP)", "CRITICAL"),

        # ==========================================
        # ISO/IEC 27001 (10 Controls)
        # ==========================================
        ("ISO", "A.5.15", "Access control: Restrict broad access rights", 'IAM policy contains Action: "*" and Resource: "*"', "CRITICAL"),
        ("ISO", "A.5.17", "Authentication information: Secure log-on procedures", "MFA device not configured for user", "HIGH"),
        ("ISO", "A.8.11", "Data masking: Storage encryption for sensitive data (S3)", "S3 ServerSideEncryptionConfiguration is missing or false", "HIGH"),
        ("ISO", "A.8.11", "Data masking: Storage encryption for sensitive data (EBS)", "EBS volume Encrypted flag set to False", "HIGH"),
        ("ISO", "A.8.11", "Data masking: Storage encryption for sensitive data (RDS)", "RDS StorageEncrypted flag set to False", "HIGH"),
        ("ISO", "A.8.12", "Data leakage prevention: S3 public access blocked", "S3 BlockPublicAcls or IgnorePublicAcls set to False", "CRITICAL"),
        ("ISO", "A.8.12", "Data leakage prevention: RDS public access blocked", "RDS PubliclyAccessible flag set to True", "CRITICAL"),
        ("ISO", "A.8.16", "Monitoring activities: Event logging active", "CloudTrail status is stopped or deleted", "HIGH"),
        ("ISO", "A.8.20", "Network security: Secure network architectures (SSH)", "Inbound SG rule allows 0.0.0.0/0 to Port 22 (SSH)", "CRITICAL"),
        ("ISO", "A.8.20", "Network security: Secure network architectures (RDP)", "Inbound SG rule allows 0.0.0.0/0 to Port 3389 (RDP)", "CRITICAL"),

        # ==========================================
        # GDPR PRIVACY (10 Controls)
        # ==========================================
        ("GDPR", "Art. 5(1)(f)", "Integrity & Confidentiality: Restrict admin privileges", 'IAM policy contains Action: "*" and Resource: "*"', "CRITICAL"),
        ("GDPR", "Art. 25", "Data protection by design: S3 public access blocked", "S3 BlockPublicAcls or IgnorePublicAcls set to False", "CRITICAL"),
        ("GDPR", "Art. 25", "Data protection by design: RDS public access blocked", "RDS PubliclyAccessible flag set to True", "CRITICAL"),
        ("GDPR", "Art. 32(1)(a)", "Security of processing: Pseudonymisation and encryption (S3)", "S3 ServerSideEncryptionConfiguration is missing or false", "HIGH"),
        ("GDPR", "Art. 32(1)(a)", "Security of processing: Pseudonymisation and encryption (EBS)", "EBS volume Encrypted flag set to False", "HIGH"),
        ("GDPR", "Art. 32(1)(a)", "Security of processing: Pseudonymisation and encryption (RDS)", "RDS StorageEncrypted flag set to False", "HIGH"),
        ("GDPR", "Art. 32(1)(b)", "Security of processing: Ongoing confidentiality (MFA)", "MFA device not configured for user", "HIGH"),
        ("GDPR", "Art. 32(1)(b)", "Security of processing: Ongoing confidentiality (SSH)", "Inbound SG rule allows 0.0.0.0/0 to Port 22 (SSH)", "CRITICAL"),
        ("GDPR", "Art. 32(1)(b)", "Security of processing: Ongoing confidentiality (RDP)", "Inbound SG rule allows 0.0.0.0/0 to Port 3389 (RDP)", "CRITICAL"),
        ("GDPR", "Art. 33", "Notification of breach: Audit logs enabled", "CloudTrail status is stopped or deleted", "HIGH"),

        # ==========================================
        # DPDPA 2023 [INDIA] (10 Controls)
        # ==========================================
        ("DPDPA", "Sec. 8(1)", "Data Fiduciary compliance: Restrict broad admin access", 'IAM policy contains Action: "*" and Resource: "*"', "CRITICAL"),
        ("DPDPA", "Sec. 8(1)", "Data Fiduciary compliance: Multi-factor authentication", "MFA device not configured for user", "HIGH"),
        ("DPDPA", "Sec. 8(4)", "Appropriate technical measures: S3 public access blocked", "S3 BlockPublicAcls or IgnorePublicAcls set to False", "CRITICAL"),
        ("DPDPA", "Sec. 8(4)", "Appropriate technical measures: RDS public access blocked", "RDS PubliclyAccessible flag set to True", "CRITICAL"),
        ("DPDPA", "Sec. 8(5)", "Protect personal data: Prevent breach via network (SSH)", "Inbound SG rule allows 0.0.0.0/0 to Port 22 (SSH)", "CRITICAL"),
        ("DPDPA", "Sec. 8(5)", "Protect personal data: Prevent breach via network (RDP)", "Inbound SG rule allows 0.0.0.0/0 to Port 3389 (RDP)", "CRITICAL"),
        ("DPDPA", "Sec. 8(5)", "Protect personal data: Reasonable safeguards (S3 Encryption)", "S3 ServerSideEncryptionConfiguration is missing or false", "HIGH"),
        ("DPDPA", "Sec. 8(5)", "Protect personal data: Reasonable safeguards (EBS Encryption)", "EBS volume Encrypted flag set to False", "HIGH"),
        ("DPDPA", "Sec. 8(5)", "Protect personal data: Reasonable safeguards (RDS Encryption)", "RDS StorageEncrypted flag set to False", "HIGH"),
        ("DPDPA", "Sec. 8(6)", "Personal data breach notification: Audit logs enabled", "CloudTrail status is stopped or deleted", "HIGH")
    ]
    
    # 4. Insert the rules
    cursor.executemany('''
        INSERT INTO frameworks (framework, control_id, description, trigger, severity)
        VALUES (?, ?, ?, ?, ?)
    ''', rules)
    
    conn.commit()
    conn.close()
    print("[+] All 40 Framework rules seeded successfully into driftwatch.db!")

if __name__ == "__main__":
    seed_db()