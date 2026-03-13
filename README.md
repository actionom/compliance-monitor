# 🛡️ SME Compliance Monitor

**A cloud-hosted, multi-framework compliance monitoring platform for Small and Medium Enterprises.**

[![Live Demo](https://img.shields.io/badge/Live%20Demo-Streamlit%20Cloud-FF4B4B?style=for-the-badge&logo=streamlit)](https://sme-compliance-monitor.streamlit.app)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-Commercial-1F497D?style=for-the-badge)](mailto:actionom@gmail.com)

---

## 📋 Overview

The SME Compliance Monitor ingests security logs from hybrid on-premises and cloud infrastructure, automatically maps violations to four regulatory frameworks, and produces client-branded audit reports — all from a single cloud-hosted dashboard.

Built for cybersecurity consultants, compliance officers, and IT service providers who need to deliver audit-grade compliance assessments to SME clients efficiently and professionally.

---

## ✅ Key Capabilities

| Capability | Detail |
|---|---|
| 🔐 Secure Login | bcrypt-hashed credentials with licence expiry per client |
| 📥 Hybrid Log Ingestion | Windows Event Log, Azure AD, Firewall, EDR, Generic CSV |
| 🔍 Violation Detection | 15 compliance controls evaluated automatically |
| 📊 Live Dashboard | Real-time KPIs, charts, severity heatmaps |
| 🎯 Framework Posture | Compliance scores across 4 frameworks simultaneously |
| 🚨 SLA Escalation | Automatic escalation after 4h Critical / 24h High / 72h Medium |
| 📄 PDF Audit Reports | Client-branded, audit-grade reports generated on demand |
| 📧 Email Alerting | Automated HTML alert emails with violation summary |
| ⬇️ Evidence Export | Full violation dataset downloadable as CSV |
| 🌐 Cloud Deployed | 24/7 availability — no client installation required |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    CLIENT BROWSER                           │
│              https://sme-compliance-monitor.streamlit.app   │
└─────────────────────┬───────────────────────────────────────┘
                      │
              ┌───────▼────────┐
              │  AUTH LAYER    │  bcrypt + licence expiry
              │  (auth.py)     │
              └───────┬────────┘
                      │
        ┌─────────────▼──────────────┐
        │      STREAMLIT DASHBOARD   │
        │         (app.py)           │
        └──┬──────────┬──────────────┘
           │          │
    ┌──────▼──┐  ┌────▼────────┐
    │  DATA   │  │   POLICY    │
    │COLLECTOR│  │   ENGINE    │
    └──────┬──┘  └────┬────────┘
           │          │
    ┌──────▼──────────▼────────┐
    │     CONTROL MATRIX       │
    │  15 controls × 4 frameworks│
    └──────────────────────────┘
           │          │
    ┌──────▼──┐  ┌────▼──────────┐
    │  ALERT  │  │    REPORT     │
    │MANAGER  │  │  GENERATOR    │
    └─────────┘  └───────────────┘
```

---

## 🔧 Technology Stack

| Component | Technology |
|---|---|
| Backend | Python 3.11+ |
| Dashboard | Streamlit 1.35+ |
| Visualisation | Plotly 5.22+ |
| PDF Generation | FPDF2 2.7.9+ |
| Authentication | bcrypt 4.1+ |
| Data Simulation | Faker 25.0+ |
| Email Alerts | Gmail SMTP (smtplib) |
| Deployment | Streamlit Community Cloud |
| Version Control | GitHub (CI/CD auto-deploy) |

---

## 📐 Compliance Frameworks

| Framework | Version | Coverage |
|---|---|---|
| **UK GDPR / Data Protection Act 2018** | Current | Articles 5, 25, 28, 32, 33, 44 |
| **ISO/IEC 27001** | 2022 | Annex A — 15 controls mapped |
| **NIST Cybersecurity Framework** | 2.0 (Feb 2024) | Identify, Protect, Detect, Respond |
| **Cyber Essentials (NCSC)** | Current | All 5 control domains |

---

## 🗂️ Project Structure

```
compliance_monitor/
├── app.py                    # Main Streamlit dashboard
├── requirements.txt          # Python dependencies
├── START_COMPLIANCE_MONITOR.bat  # Windows one-click launcher
│
└── modules/
    ├── __init__.py
    ├── auth.py               # Authentication & licence management
    ├── control_matrix.py     # 15-control compliance rule base
    ├── data_collector.py     # Log ingestion & simulation engine
    ├── policy_engine.py      # Violation detection & posture scoring
    ├── alert_manager.py      # SLA escalation & triage
    ├── report_generator.py   # Client-branded PDF report generation
    ├── client_ingestion.py   # Real client log file processing
    └── email_alerts.py       # Automated HTML email alerting
```

---

## 🚀 Quick Start — Local Deployment

```bash
# 1. Clone the repository
git clone https://github.com/actionom/compliance-monitor.git
cd compliance-monitor

# 2. Install dependencies
python -m pip install -r requirements.txt

# 3. Launch dashboard
python -m streamlit run app.py
```

Open your browser at **http://localhost:8501**

**Default credentials:**
| Username | Password | Access |
|---|---|---|
| `admin` | `Admin@2026` | Full admin access |
| `demo` | `Demo@2026` | Demo / prospect access |

---

## 📥 Supported Log Sources

| Source | Format | How to Export |
|---|---|---|
| Windows Event Log | CSV | `eventvwr.msc` → Save All Events As → CSV |
| Azure AD Sign-in Logs | CSV | Azure Portal → Azure AD → Sign-in logs → Download |
| Azure AD Audit Logs | CSV | Azure Portal → Azure AD → Audit logs → Download |
| Firewall (pfSense/Fortinet) | CSV | Management console → Logs → Export |
| Endpoint EDR | CSV | CrowdStrike/Defender/Sophos → Detections → Export |
| Generic | CSV/JSON | Any system — requires: timestamp, event_type columns |

---

## 📊 Compliance Control Matrix

| ID | Control | Severity | Frameworks |
|---|---|---|---|
| CM-001 | Unauthorised Access Attempt | High | GDPR Art.32, ISO A.8.3, NIST PR.AC-7 |
| CM-002 | Unencrypted Data Transmission | Critical | GDPR Art.32(1)(a), ISO A.8.24 |
| CM-003 | Excessive Privilege Assignment | High | GDPR Art.25, ISO A.8.2 |
| CM-004 | Missing Security Patch | High | GDPR Art.32(1)(d), ISO A.8.8, Cyber Essentials |
| CM-005 | Data Retention Policy Breach | Critical | GDPR Art.5(1)(e), ISO A.5.33 |
| CM-006 | No Multi-Factor Authentication | High | GDPR Art.32, ISO A.8.5, Cyber Essentials |
| CM-007 | Audit Log Disabled/Tampered | Critical | GDPR Art.5(2), ISO A.8.15 |
| CM-008 | Firewall Misconfiguration | Critical | GDPR Art.32, ISO A.8.20, Cyber Essentials |
| CM-009 | Personal Data Exfiltration Risk | Critical | GDPR Art.44, ISO A.5.14 |
| CM-010 | Inactive Account Not Disabled | Medium | GDPR Art.5(1)(e), ISO A.8.3 |
| CM-011 | Malware Detection Event | Critical | GDPR Art.32(1)(b), ISO A.8.7, Cyber Essentials |
| CM-012 | Third-Party Vendor Risk | High | GDPR Art.28, ISO A.5.19 |
| CM-013 | Incident Response Delay | High | GDPR Art.33, ISO A.5.26 |
| CM-014 | Backup Failure | High | GDPR Art.32(1)(c), ISO A.8.13 |
| CM-015 | Unmanaged Device on Network | Medium | GDPR Art.32, ISO A.5.9, Cyber Essentials |

---

## 📧 Email Alerting Setup

1. Enable 2-Factor Authentication on your Gmail account
2. Go to **Google Account → Security → App Passwords**
3. Generate an App Password for "Mail"
4. In Streamlit Cloud → **Settings → Secrets**, add:

```toml
GMAIL_APP_PASSWORD = "xxxx xxxx xxxx xxxx"
```

Email alerts include: violation summary table, framework posture bars, and a direct link to the live dashboard.

---

## ➕ Adding a New Client

1. Generate a password hash:
```bash
python -c "import bcrypt; print(bcrypt.hashpw(b'YourPassword', bcrypt.gensalt()).decode())"
```

2. Add to `modules/auth.py` under `CLIENT_CREDENTIALS`:
```python
"clientusername": {
    "password_hash": "paste-hash-here",
    "client_name":   "Client Company Ltd",
    "expiry":        date(2027, 3, 31),
    "plan":          "Standard",
},
```

3. Commit to GitHub — change takes effect within 2 minutes.

To **revoke access**: change expiry to a past date.

---

## 💼 Commercial Services

This platform is available as a managed compliance monitoring service.

| Package | Description | Price |
|---|---|---|
| **Basic Audit** | One-off compliance assessment + PDF report | From £350 |
| **Standard** | Monthly monitoring + SLA alerts + monthly report | From £500/month |
| **Premium** | Continuous monitoring + incident detection + quarterly audit | From £2,000/project |

**Contact:**
📧 actionom@gmail.com
📞 +44 7440 135240
👤 Opoku Mensah | Cybersecurity Consultant

---

## 📄 Disclaimer

This platform is a commercial product. Unauthorised access, redistribution, or reproduction of this software is prohibited. All client data processed through this platform is handled in accordance with UK GDPR and the Data Protection Act 2018.

---

*Built and maintained by Opoku Mensah | Cybersecurity Consultant*
