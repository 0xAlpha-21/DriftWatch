# DriftWatch: Continuous Cloud Configuration Compliance Drift Detector

> A lightweight, open-source continuous compliance drift detection framework mapped to multi-regulation controls (CIS Benchmarks and ISO 27001 Annex A).

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Frameworks](https://img.shields.io/badge/Standards-CIS%20AWS%20v3.0%20%7C%20ISO%2027001%3A2022-orange)](https://www.iso.org/)

---

## 🚀 Overview

Cloud misconfigurations remain a leading cause of security breaches. While initial deployments are often secure, routine operational tweaks, debugging sessions, and quick fixes frequently cause **configuration drift**—a resource silently moving out of compliance weeks before the next scheduled quarterly audit.

Commercial Cloud Security Posture Management (CSPM) solutions are often cost-prohibitive for startups and lean engineering teams. **DriftWatch** provides a lightweight, open-source alternative that runs locally or on minimal cloud tiers, performing continuous state inspection, temporal diff tracking, and multi-framework compliance mapping.

---

## ✨ Key Features

* **Multi-Framework Control Mapping:** Automatically maps raw cloud configurations simultaneously to **CIS AWS Foundations Benchmarks** and **ISO 27001:2022 Annex A** control identifiers.
* **Temporal Diff Engine:** Beyond point-in-time scanning, DriftWatch stores timestamped snapshots to detect *when* a resource drifted from a previously verified compliant baseline.
* **Serverless Local Storage:** Built on SQLite and native Python JSON parsing—no heavy database installation or server infrastructure required.
* **Interactive Dashboard:** Includes a built-in **Streamlit** user interface to visualize current resource compliance, active violations, and a chronological drift timeline.
* **Zero-Cost Design:** Relies exclusively on read-only AWS API calls (`boto3`) and operates fully within standard free-tier parameters.

---

## 🛠️ Tech Stack

* **Language:** Python 3.8+
* **Cloud SDK:** `boto3` (AWS API Polling)
* **Storage:** SQLite & Python Standard JSON Library
* **UI/Visualization:** Streamlit & Pandas
* **Testing / IaC:** Terraform (for provisioning isolated test environments)

---

## 📊 Unified Control Mapping Sample

| Resource Type | Configuration Item | CIS AWS v3.0 | ISO 27001:2022 | Severity | Drift Trigger Condition |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **EC2 / VPC** | Restrict SSH (Port 22) | 5.2 | A.8.21 (Network Security) | High | `IpRanges` includes `0.0.0.0/0` on Port 22 |
| **S3** | Block Public Access | 1.20 | A.8.24 / A.5.15 | Critical | `BlockPublicAcls` or `IgnorePublicAcls` is `False` |
| **IAM** | MFA Enabled for Users | 1.10 | A.5.17 (Authentication) | High | `PasswordEnabled` is True, `MFAActive` is False |

---

## ⚙️ Installation & Setup

### 1. Clone the Repository
```bash
git clone [https://github.com/your-username/driftwatch.git](https://github.com/your-username/driftwatch.git)
cd driftwatch