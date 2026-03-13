"""
compliance_monitor/modules/data_collector.py
---------------------------------------------
Simulates realistic log ingestion from hybrid SME sources:
  - On-premises: Active Directory, Firewall, File Server, Endpoint EDR
  - Cloud: Azure AD / Entra, M365, Cloud Storage, SaaS Applications

Author : Opoku Mensah (w25035430)
Version: 1.0.0
"""

import random
import uuid
from datetime import datetime, timedelta
from faker import Faker

fake = Faker("en_GB")

SOURCE_SYSTEMS = {
    "active_directory": "On-Premises",
    "firewall": "On-Premises",
    "endpoint": "On-Premises",
    "on_prem_server": "On-Premises",
    "file_server": "On-Premises",
    "network_monitor": "On-Premises",
    "dhcp": "On-Premises",
    "backup_system": "On-Premises",
    "siem": "On-Premises",
    "cloud_iam": "Cloud",
    "cloud_storage": "Cloud",
    "cloud_compute": "Cloud",
    "cloud_logging": "Cloud",
    "saas_applications": "Cloud",
    "dlp": "Cloud",
    "vendor_portal": "Cloud",
    "ticketing_system": "Cloud",
    "database": "Cloud",
    "vpn": "Hybrid",
}

SME_USERS = [
    "j.smith", "a.patel", "l.chen", "m.okafor", "r.jones",
    "k.williams", "s.thompson", "d.hassan", "b.garcia", "c.young",
    "admin", "svc_backup", "svc_monitoring", "vendor_acme", "vendor_techsupport",
]

SME_HOSTS = [
    "WS-FINANCE-01", "WS-HR-02", "WS-SALES-03", "WS-DEV-04",
    "SRV-DC-01", "SRV-FILE-01", "SRV-APP-01", "SRV-BACKUP-01",
    "AZURE-VM-PROD", "AZURE-VM-DEV", "M365-TENANT",
]

VENDOR_NAMES = ["ACME IT Services", "TechSupport Ltd", "CloudSolutions UK", "NetSecure Partners"]


def random_ip(internal=True):
    if internal:
        return f"192.168.{random.randint(1, 10)}.{random.randint(1, 254)}"
    return fake.ipv4_public()


def random_timestamp(days_back=30):
    delta = timedelta(
        days=random.randint(0, days_back),
        hours=random.randint(0, 23),
        minutes=random.randint(0, 59),
        seconds=random.randint(0, 59),
    )
    return (datetime.now() - delta).strftime("%Y-%m-%d %H:%M:%S")


def generate_event(control_id: str, source: str, count: int = 1) -> list:
    """Generate synthetic log events for a given control ID and source system."""
    events = []
    for _ in range(count):
        base = {
            "event_id": str(uuid.uuid4())[:8].upper(),
            "timestamp": random_timestamp(),
            "source_system": source,
            "source_tier": SOURCE_SYSTEMS.get(source, "Unknown"),
            "control_id": control_id,
            "hostname": random.choice(SME_HOSTS),
            "user": random.choice(SME_USERS),
            "src_ip": random_ip(internal=random.choice([True, False])),
        }

        if control_id == "CM-001":
            base.update({
                "detail": f"Failed login attempts: {random.randint(5, 50)}",
                "dest_ip": random_ip(internal=True),
                "protocol": "LDAP/Kerberos",
            })
        elif control_id == "CM-002":
            base.update({
                "detail": f"HTTP traffic on port {random.choice([80, 21, 23])} containing PII keywords",
                "data_size_kb": random.randint(10, 5000),
                "protocol": random.choice(["HTTP", "FTP", "TELNET"]),
            })
        elif control_id == "CM-003":
            base.update({
                "detail": f"Admin role assigned to {base['user']} — no change ticket found",
                "role_assigned": random.choice(["Domain Admin", "Global Admin", "Root", "Sudo"]),
                "approved_by": "N/A",
            })
        elif control_id == "CM-004":
            cve = f"CVE-{random.randint(2022, 2025)}-{random.randint(1000, 99999)}"
            base.update({
                "detail": f"Unpatched vulnerability {cve} on {base['hostname']}",
                "cve_id": cve,
                "cvss_score": round(random.uniform(6.0, 9.8), 1),
                "days_overdue": random.randint(31, 180),
            })
        elif control_id == "CM-005":
            base.update({
                "detail": f"Personal data records found with creation date {random.randint(2, 7)} years ago",
                "record_count": random.randint(100, 50000),
                "data_category": random.choice(["Health Records", "HR Data", "Customer PII", "Financial Records"]),
                "retention_days_exceeded": random.randint(30, 1825),
            })
        elif control_id == "CM-006":
            base.update({
                "detail": f"MFA not enrolled for {base['user']} on sensitive application",
                "application": random.choice(["M365", "Azure Portal", "CRM", "HR System", "Finance App"]),
                "last_login_ip": random_ip(internal=False),
            })
        elif control_id == "CM-007":
            base.update({
                "detail": f"Audit log on {base['hostname']} disabled or {random.randint(1, 72)} hours of records missing",
                "log_gap_hours": random.randint(1, 72),
                "last_valid_log": random_timestamp(days_back=3),
            })
        elif control_id == "CM-008":
            base.update({
                "detail": f"Firewall rule allows unrestricted inbound on port {random.choice([22, 3389, 445, 1433, 3306])}",
                "rule_id": f"FW-RULE-{random.randint(100, 999)}",
                "port": random.choice([22, 3389, 445, 1433, 3306]),
                "direction": "Inbound",
                "action": "ALLOW",
            })
        elif control_id == "CM-009":
            base.update({
                "detail": f"Data transfer of {random.randint(500, 50000)} MB to external IP",
                "dest_ip": random_ip(internal=False),
                "data_size_mb": random.randint(500, 50000),
                "dest_country": random.choice(["Unknown", "CN", "RU", "BR", "NG"]),
            })
        elif control_id == "CM-010":
            base.update({
                "detail": f"Account {base['user']} inactive for {random.randint(90, 365)} days — still enabled",
                "inactive_days": random.randint(90, 365),
                "last_logon": random_timestamp(days_back=365),
            })
        elif control_id == "CM-011":
            base.update({
                "detail": f"Malware detected on {base['hostname']}: {random.choice(['Ransomware', 'Trojan', 'Worm', 'Spyware'])}",
                "malware_name": random.choice(["LockBit.variant", "Emotet.dropper", "AgentTesla", "Qakbot"]),
                "remediation_status": random.choice(["Pending", "Failed", "Quarantined"]),
                "detection_engine": random.choice(["CrowdStrike", "Defender", "Sophos"]),
            })
        elif control_id == "CM-012":
            vendor = random.choice(VENDOR_NAMES)
            base.update({
                "detail": f"Vendor '{vendor}' accessing systems — DPA expired or not on file",
                "vendor_name": vendor,
                "dpa_status": random.choice(["Expired", "Not Found", "Unsigned"]),
                "last_assessment_date": random_timestamp(days_back=400),
            })
        elif control_id == "CM-013":
            base.update({
                "detail": f"Incident {base['event_id']} breached {random.randint(4, 48)}-hour escalation SLA",
                "incident_severity": random.choice(["Critical", "High"]),
                "sla_breach_hours": random.randint(1, 44),
                "assigned_to": random.choice(SME_USERS),
            })
        elif control_id == "CM-014":
            base.update({
                "detail": f"Scheduled backup failed on {base['hostname']} — last verified: {random.randint(2, 14)} days ago",
                "backup_type": random.choice(["Full", "Incremental", "Differential"]),
                "last_success_days": random.randint(2, 14),
                "error_code": random.choice(["ERR_TIMEOUT", "ERR_DISK_FULL", "ERR_AGENT_OFFLINE"]),
            })
        elif control_id == "CM-015":
            base.update({
                "detail": f"Unregistered device with MAC {fake.mac_address()} connected to network",
                "mac_address": fake.mac_address(),
                "switch_port": f"SW{random.randint(1, 4)}/P{random.randint(1, 48)}",
                "device_type": random.choice(["Unknown Laptop", "Mobile Device", "IoT Sensor", "BYOD"]),
            })

        events.append(base)
    return events


def collect_all_events(events_per_control: int = 3) -> list:
    """
    Simulate ingestion from all source systems and all control types.
    Returns a flat list of event dictionaries.
    """
    from .control_matrix import CONTROL_MATRIX

    all_events = []
    for control in CONTROL_MATRIX:
        sources = control["source_systems"]
        for source in sources[:2]:  # Use up to 2 sources per control
            count = random.randint(1, events_per_control)
            all_events.extend(generate_event(control["control_id"], source, count))

    # Sort by timestamp descending
    all_events.sort(key=lambda x: x["timestamp"], reverse=True)
    return all_events
