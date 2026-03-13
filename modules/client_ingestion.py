"""
compliance_monitor/modules/client_ingestion.py
-----------------------------------------------
Client Data Ingestion Engine.
Accepts real client log exports (CSV/JSON) from:
  - Windows Event Logs
  - Azure AD / Entra ID Sign-in Logs
  - Firewall Logs (pfSense, Fortinet, Cisco)
  - Endpoint EDR exports
  - Generic syslog CSV exports

Maps client log fields to compliance control violations
and feeds them into the existing policy engine pipeline.

Author : Opoku Mensah (w25035430)
Version: 2.0.0
"""

import pandas as pd
import json
import uuid
from datetime import datetime
from io import StringIO, BytesIO


# ── Log Source Definitions ────────────────────────────────────────────────────
LOG_SOURCE_PROFILES = {
    "Windows Event Log": {
        "description": "Exported from Event Viewer (eventvwr.msc) as CSV",
        "required_columns": ["TimeCreated", "Id", "LevelDisplayName", "Message"],
        "optional_columns": ["Computer", "UserId", "ProviderName"],
        "source_system": "active_directory",
        "source_tier": "On-Premises",
        "event_id_map": {
            "4625": "CM-001",   # Failed logon
            "4720": "CM-003",   # User account created
            "4732": "CM-003",   # Member added to privileged group
            "4698": "CM-003",   # Scheduled task created
            "1102": "CM-007",   # Audit log cleared
            "4719": "CM-007",   # Audit policy changed
            "4776": "CM-001",   # Credential validation
            "4648": "CM-001",   # Logon using explicit credentials
        }
    },
    "Azure AD Sign-in Logs": {
        "description": "Downloaded from Azure Portal > Azure AD > Sign-in logs > CSV",
        "required_columns": ["Date (UTC)", "User", "Application", "Status"],
        "optional_columns": ["IP address", "Location", "Client app", "Conditional access"],
        "source_system": "cloud_iam",
        "source_tier": "Cloud",
        "field_rules": {
            "Status": {"Failure": "CM-001", "Interrupted": "CM-001"},
            "Conditional access": {"Not applied": "CM-006", "not applied": "CM-006"},
            "MFA result": {"MFA requirement satisfied by claim": None,
                          "": "CM-006", "MFA not required": "CM-006"},
        }
    },
    "Firewall Logs (pfSense/Generic)": {
        "description": "Exported from firewall management console as CSV",
        "required_columns": ["timestamp", "action", "src_ip", "dst_port"],
        "optional_columns": ["dst_ip", "protocol", "interface", "rule_id"],
        "source_system": "firewall",
        "source_tier": "On-Premises",
        "field_rules": {
            "action": {"BLOCK": None, "PASS": None},
            "dst_port": {
                "22": "CM-008", "23": "CM-008", "3389": "CM-008",
                "445": "CM-008", "1433": "CM-008", "3306": "CM-008",
                "80": "CM-002", "21": "CM-002"
            }
        }
    },
    "Endpoint EDR Export": {
        "description": "Exported from CrowdStrike, Defender, or Sophos as CSV",
        "required_columns": ["detection_time", "severity", "device_name", "description"],
        "optional_columns": ["user", "process_name", "file_path", "action_taken", "cve_id"],
        "source_system": "endpoint",
        "source_tier": "On-Premises",
        "field_rules": {
            "severity": {
                "Critical": "CM-011", "High": "CM-011",
                "Medium": "CM-004", "Low": "CM-004"
            },
            "description_keywords": {
                "malware": "CM-011", "ransomware": "CM-011",
                "virus": "CM-011", "trojan": "CM-011",
                "patch": "CM-004", "vulnerability": "CM-004",
                "cve": "CM-004", "exploit": "CM-004",
                "unencrypted": "CM-002", "http": "CM-002",
            }
        }
    },
    "Azure AD Audit Logs": {
        "description": "Downloaded from Azure Portal > Azure AD > Audit logs > CSV",
        "required_columns": ["Date (UTC)", "Service", "Category", "Activity", "Status"],
        "optional_columns": ["Actor", "Target", "Modified properties"],
        "source_system": "cloud_iam",
        "source_tier": "Cloud",
        "field_rules": {
            "Activity": {
                "Add member to role": "CM-003",
                "Reset password": "CM-001",
                "Disable account": "CM-010",
                "Delete user": "CM-010",
                "Update policy": "CM-007",
                "Add application": "CM-012",
            }
        }
    },
    "Generic CSV Upload": {
        "description": "Any CSV with at minimum: timestamp, event_type, hostname, username",
        "required_columns": ["timestamp", "event_type"],
        "optional_columns": ["hostname", "username", "src_ip", "detail", "severity"],
        "source_system": "siem",
        "source_tier": "Hybrid",
        "event_type_map": {
            "failed_login": "CM-001", "brute_force": "CM-001",
            "admin_privilege": "CM-003", "privilege_escalation": "CM-003",
            "unencrypted_traffic": "CM-002", "http_data": "CM-002",
            "patch_missing": "CM-004", "vulnerability": "CM-004",
            "data_retention": "CM-005", "old_data": "CM-005",
            "no_mfa": "CM-006", "mfa_bypass": "CM-006",
            "log_cleared": "CM-007", "audit_disabled": "CM-007",
            "firewall_open": "CM-008", "port_open": "CM-008",
            "data_exfil": "CM-009", "large_transfer": "CM-009",
            "inactive_account": "CM-010", "dormant_user": "CM-010",
            "malware": "CM-011", "virus": "CM-011",
            "vendor_access": "CM-012", "third_party": "CM-012",
            "incident_delay": "CM-013", "sla_breach": "CM-013",
            "backup_fail": "CM-014", "backup_error": "CM-014",
            "unknown_device": "CM-015", "rogue_device": "CM-015",
        }
    }
}


# ── CSV Templates ─────────────────────────────────────────────────────────────
CSV_TEMPLATES = {
    "Windows Event Log": """TimeCreated,Id,LevelDisplayName,Message,Computer,UserId,ProviderName
2026-03-13 08:15:22,4625,Warning,An account failed to log on.,WS-FINANCE-01,j.smith,Microsoft-Windows-Security-Auditing
2026-03-13 08:16:45,4625,Warning,An account failed to log on.,WS-FINANCE-01,j.smith,Microsoft-Windows-Security-Auditing
2026-03-13 08:17:01,4625,Warning,An account failed to log on.,WS-FINANCE-01,j.smith,Microsoft-Windows-Security-Auditing
2026-03-13 09:30:00,4732,Information,A member was added to a security-enabled group.,SRV-DC-01,admin,Microsoft-Windows-Security-Auditing
2026-03-13 10:00:00,1102,Critical,The audit log was cleared.,SRV-DC-01,admin,Microsoft-Windows-Security-Auditing
2026-03-13 11:15:00,4625,Warning,An account failed to log on.,SRV-APP-01,r.jones,Microsoft-Windows-Security-Auditing""",

    "Azure AD Sign-in Logs": """Date (UTC),User,Application,Status,IP address,Location,Client app,Conditional access
2026-03-13 07:00:00,j.smith@company.com,Microsoft 365,Failure,185.23.45.67,Unknown,Browser,Not applied
2026-03-13 07:05:00,a.patel@company.com,Azure Portal,Success,192.168.1.10,London UK,Mobile Apps,not applied
2026-03-13 08:30:00,l.chen@company.com,SharePoint,Failure,91.108.4.100,Russia,Browser,Not applied
2026-03-13 09:00:00,m.okafor@company.com,Teams,Success,192.168.1.25,London UK,Desktop app,
2026-03-13 10:15:00,admin@company.com,Azure Portal,Success,203.0.113.50,Unknown,Browser,Not applied""",

    "Firewall Logs (pfSense/Generic)": """timestamp,action,src_ip,dst_port,dst_ip,protocol,interface,rule_id
2026-03-13 06:00:00,PASS,0.0.0.0/0,3389,192.168.1.10,TCP,WAN,FW-RULE-201
2026-03-13 06:30:00,PASS,0.0.0.0/0,22,192.168.1.15,TCP,WAN,FW-RULE-202
2026-03-13 07:00:00,PASS,192.168.1.50,80,10.0.0.5,TCP,LAN,FW-RULE-150
2026-03-13 07:30:00,PASS,0.0.0.0/0,445,192.168.1.20,TCP,WAN,FW-RULE-203
2026-03-13 08:00:00,PASS,192.168.1.30,21,185.23.45.67,TCP,LAN,FW-RULE-151
2026-03-13 09:00:00,BLOCK,203.0.113.10,3306,192.168.1.5,TCP,WAN,FW-RULE-001""",

    "Endpoint EDR Export": """detection_time,severity,device_name,description,user,process_name,action_taken,cve_id
2026-03-13 02:00:00,Critical,WS-FINANCE-01,Ransomware behaviour detected in process,j.smith,svchost.exe,Quarantined,
2026-03-13 03:15:00,High,SRV-APP-01,Trojan dropper identified,svc_backup,powershell.exe,Pending,
2026-03-13 05:00:00,High,WS-HR-02,Missing critical patch - vulnerability exploitable,a.patel,,,CVE-2025-12345
2026-03-13 06:30:00,Medium,SRV-DC-01,Software vulnerability detected,admin,,,CVE-2024-98765
2026-03-13 08:00:00,Critical,WS-SALES-03,Malware signature match - AgentTesla,r.jones,outlook.exe,Failed,""",

    "Generic CSV Upload": """timestamp,event_type,hostname,username,src_ip,detail,severity
2026-03-13 08:00:00,failed_login,WS-FINANCE-01,j.smith,192.168.1.10,5 failed login attempts,High
2026-03-13 08:30:00,no_mfa,AZURE-VM-PROD,a.patel,185.23.45.67,MFA not configured for Azure Portal,High
2026-03-13 09:00:00,unencrypted_traffic,SRV-FILE-01,svc_backup,192.168.1.5,HTTP traffic containing PII detected,Critical
2026-03-13 09:30:00,backup_fail,SRV-BACKUP-01,admin,192.168.1.20,Scheduled backup job failed - disk full,High
2026-03-13 10:00:00,inactive_account,SRV-DC-01,old.user,192.168.1.1,Account inactive for 120 days still enabled,Medium
2026-03-13 10:30:00,unknown_device,WS-DEV-04,,,Unregistered device MAC 00:1A:2B:3C:4D:5E connected,Medium"""
}


# ── Ingestion Engine ──────────────────────────────────────────────────────────

def _safe_str(val):
    return str(val).strip() if pd.notna(val) else ""


def _ingest_windows_event_log(df: pd.DataFrame, profile: dict) -> list:
    events = []
    event_id_map = profile.get("event_id_map", {})
    for _, row in df.iterrows():
        event_id = _safe_str(row.get("Id", ""))
        control_id = event_id_map.get(event_id)

        # Also scan message for keywords if no direct event ID match
        if not control_id:
            msg = _safe_str(row.get("Message", "")).lower()
            if "failed" in msg or "failure" in msg:
                control_id = "CM-001"
            elif "cleared" in msg or "disabled" in msg:
                control_id = "CM-007"
            elif "privilege" in msg or "admin" in msg:
                control_id = "CM-003"

        if control_id:
            events.append({
                "event_id": str(uuid.uuid4())[:8].upper(),
                "timestamp": _safe_str(row.get("TimeCreated", str(datetime.now()))),
                "source_system": profile["source_system"],
                "source_tier": profile["source_tier"],
                "control_id": control_id,
                "hostname": _safe_str(row.get("Computer", "Unknown")),
                "user": _safe_str(row.get("UserId", "Unknown")),
                "src_ip": "N/A",
                "detail": _safe_str(row.get("Message", ""))[:200],
                "event_raw_id": event_id,
            })
    return events


def _ingest_azure_signin(df: pd.DataFrame, profile: dict) -> list:
    events = []
    for _, row in df.iterrows():
        control_id = None
        status = _safe_str(row.get("Status", ""))
        ca = _safe_str(row.get("Conditional access", "")).lower()
        mfa = _safe_str(row.get("MFA result", "")).lower()

        if status.lower() in ["failure", "interrupted"]:
            control_id = "CM-001"
        elif "not applied" in ca or ca == "":
            control_id = "CM-006"
        elif mfa in ["", "mfa not required"]:
            control_id = "CM-006"

        if control_id:
            events.append({
                "event_id": str(uuid.uuid4())[:8].upper(),
                "timestamp": _safe_str(row.get("Date (UTC)", str(datetime.now()))),
                "source_system": profile["source_system"],
                "source_tier": profile["source_tier"],
                "control_id": control_id,
                "hostname": _safe_str(row.get("Application", "Unknown")),
                "user": _safe_str(row.get("User", "Unknown")),
                "src_ip": _safe_str(row.get("IP address", "N/A")),
                "detail": f"Sign-in {status} from {_safe_str(row.get('Location','Unknown'))} - CA: {_safe_str(row.get('Conditional access','N/A'))}",
                "location": _safe_str(row.get("Location", "")),
            })
    return events


def _ingest_firewall(df: pd.DataFrame, profile: dict) -> list:
    events = []
    risky_ports = {"22", "23", "3389", "445", "1433", "3306", "80", "21", "8080", "5900"}
    for _, row in df.iterrows():
        dst_port = _safe_str(row.get("dst_port", ""))
        action = _safe_str(row.get("action", "")).upper()
        control_id = None

        if dst_port in {"3389", "22", "445", "1433", "3306", "23"} and action == "PASS":
            control_id = "CM-008"
        elif dst_port in {"80", "21", "8080"} and action == "PASS":
            control_id = "CM-002"
        elif dst_port in risky_ports and action == "PASS":
            control_id = "CM-008"

        if control_id:
            events.append({
                "event_id": str(uuid.uuid4())[:8].upper(),
                "timestamp": _safe_str(row.get("timestamp", str(datetime.now()))),
                "source_system": profile["source_system"],
                "source_tier": profile["source_tier"],
                "control_id": control_id,
                "hostname": _safe_str(row.get("dst_ip", "Unknown")),
                "user": "N/A",
                "src_ip": _safe_str(row.get("src_ip", "N/A")),
                "detail": f"Rule {_safe_str(row.get('rule_id','N/A'))}: {action} on port {dst_port} via {_safe_str(row.get('interface','N/A'))}",
                "port": dst_port,
                "rule_id": _safe_str(row.get("rule_id", "")),
            })
    return events


def _ingest_edr(df: pd.DataFrame, profile: dict) -> list:
    events = []
    malware_keywords = ["malware", "ransomware", "trojan", "virus", "spyware", "worm", "rootkit"]
    vuln_keywords = ["patch", "vulnerability", "cve", "exploit", "missing update"]

    for _, row in df.iterrows():
        desc = _safe_str(row.get("description", "")).lower()
        severity = _safe_str(row.get("severity", "")).lower()
        cve = _safe_str(row.get("cve_id", ""))
        control_id = None

        if any(k in desc for k in malware_keywords):
            control_id = "CM-011"
        elif any(k in desc for k in vuln_keywords) or cve:
            control_id = "CM-004"
        elif severity in ["critical", "high"]:
            control_id = "CM-011"
        elif severity in ["medium", "low"]:
            control_id = "CM-004"

        if control_id:
            events.append({
                "event_id": str(uuid.uuid4())[:8].upper(),
                "timestamp": _safe_str(row.get("detection_time", str(datetime.now()))),
                "source_system": profile["source_system"],
                "source_tier": profile["source_tier"],
                "control_id": control_id,
                "hostname": _safe_str(row.get("device_name", "Unknown")),
                "user": _safe_str(row.get("user", "N/A")),
                "src_ip": "N/A",
                "detail": _safe_str(row.get("description", ""))[:200],
                "cve_id": cve,
                "action_taken": _safe_str(row.get("action_taken", "")),
                "remediation_status": _safe_str(row.get("action_taken", "Pending")) or "Pending",
            })
    return events


def _ingest_generic(df: pd.DataFrame, profile: dict) -> list:
    events = []
    event_type_map = profile.get("event_type_map", {})

    for _, row in df.iterrows():
        event_type = _safe_str(row.get("event_type", "")).lower().replace(" ", "_")
        control_id = event_type_map.get(event_type)

        # Fuzzy match if exact not found
        if not control_id:
            for key, cid in event_type_map.items():
                if key in event_type or event_type in key:
                    control_id = cid
                    break

        # Also check Activity column (Azure AD Audit Logs)
        if not control_id:
            activity = str(row.get("Activity", "")).strip()
            activity_map = {
                "Add member to role": "CM-003",
                "Reset password": "CM-001",
                "Disable account": "CM-010",
                "Delete user": "CM-010",
                "Update policy": "CM-007",
                "Add application": "CM-012",
            }
            control_id = activity_map.get(activity)

        if control_id:
            events.append({
                "event_id": str(uuid.uuid4())[:8].upper(),
                "timestamp": _safe_str(row.get("timestamp", str(datetime.now()))),
                "source_system": profile["source_system"],
                "source_tier": profile["source_tier"],
                "control_id": control_id,
                "hostname": _safe_str(row.get("hostname", "Unknown")),
                "user": _safe_str(row.get("username", "N/A")),
                "src_ip": _safe_str(row.get("src_ip", "N/A")),
                "detail": _safe_str(row.get("detail", ""))[:200],
                "severity_raw": _safe_str(row.get("severity", "")),
            })
    return events


INGESTOR_MAP = {
    "Windows Event Log": _ingest_windows_event_log,
    "Azure AD Sign-in Logs": _ingest_azure_signin,
    "Firewall Logs (pfSense/Generic)": _ingest_firewall,
    "Endpoint EDR Export": _ingest_edr,
    "Azure AD Audit Logs": _ingest_generic,
    "Generic CSV Upload": _ingest_generic,
}


def ingest_client_file(file_content: bytes, filename: str, log_source: str,
                       client_name: str = "Client") -> dict:
    """
    Main ingestion entry point.
    Accepts file bytes, filename, log source type, and client name.
    Returns dict with events, stats, and any errors.
    """
    result = {
        "client_name": client_name,
        "filename": filename,
        "log_source": log_source,
        "events": [],
        "rows_parsed": 0,
        "violations_found": 0,
        "errors": [],
        "ingestion_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    try:
        # Parse file
        if filename.endswith(".json"):
            data = json.loads(file_content.decode("utf-8", errors="replace"))
            if isinstance(data, list):
                df = pd.DataFrame(data)
            elif isinstance(data, dict):
                df = pd.DataFrame([data])
            else:
                result["errors"].append("JSON must be an array of objects or a single object.")
                return result
        else:
            try:
                df = pd.read_csv(BytesIO(file_content), encoding="utf-8", on_bad_lines="skip")
            except Exception:
                df = pd.read_csv(BytesIO(file_content), encoding="latin-1", on_bad_lines="skip")

        result["rows_parsed"] = len(df)

        if df.empty:
            result["errors"].append("File is empty or could not be parsed.")
            return result

        # Get profile and ingestor
        profile = LOG_SOURCE_PROFILES.get(log_source, LOG_SOURCE_PROFILES["Generic CSV Upload"])
        ingestor = INGESTOR_MAP.get(log_source, _ingest_generic)

        # Tag all events with client name
        events = ingestor(df, profile)
        for e in events:
            e["client_name"] = client_name

        result["events"] = events
        result["violations_found"] = len(events)

    except Exception as ex:
        result["errors"].append(f"Ingestion error: {str(ex)}")

    return result


def get_template_csv(log_source: str) -> str:
    """Return the sample CSV template for a given log source."""
    return CSV_TEMPLATES.get(log_source, CSV_TEMPLATES["Generic CSV Upload"])


def get_all_source_names() -> list:
    return list(LOG_SOURCE_PROFILES.keys())


def get_source_description(log_source: str) -> str:
    return LOG_SOURCE_PROFILES.get(log_source, {}).get("description", "")


def get_required_columns(log_source: str) -> list:
    return LOG_SOURCE_PROFILES.get(log_source, {}).get("required_columns", [])
