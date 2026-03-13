"""
compliance_monitor/modules/control_matrix.py
--------------------------------------------
Unified Compliance Control Mapping Matrix.
Maps violation types to framework clauses across:
  - UK GDPR / DPA 2018
  - ISO 27001:2022
  - NIST CSF 2.0
  - Cyber Essentials (NCSC)

Author : Opoku Mensah (w25035430)
Version: 1.0.0
"""

CONTROL_MATRIX = [
    {
        "control_id": "CM-001",
        "name": "Unauthorised Access Attempt",
        "description": "Multiple failed authentication attempts detected from a single source",
        "category": "Access Control",
        "gdpr_clause": "Article 32 – Security of processing",
        "iso27001_clause": "A.8.3 – Information access restriction",
        "nist_csf": "PR.AC-7 – Users, devices, and other assets are authenticated",
        "cyber_essentials": "Access Control – User account management",
        "default_severity": "High",
        "source_systems": ["active_directory", "cloud_iam", "vpn"],
    },
    {
        "control_id": "CM-002",
        "name": "Unencrypted Data Transmission",
        "description": "Sensitive data transmitted over unencrypted channels (HTTP/FTP)",
        "category": "Data Protection",
        "gdpr_clause": "Article 32(1)(a) – Pseudonymisation and encryption",
        "iso27001_clause": "A.8.24 – Use of cryptography",
        "nist_csf": "PR.DS-2 – Data-in-transit is protected",
        "cyber_essentials": "Patch Management – Secure configuration",
        "default_severity": "Critical",
        "source_systems": ["firewall", "network_monitor", "cloud_storage"],
    },
    {
        "control_id": "CM-003",
        "name": "Excessive Privilege Assignment",
        "description": "User account assigned admin/root privileges without documented approval",
        "category": "Access Control",
        "gdpr_clause": "Article 25 – Data protection by design and by default",
        "iso27001_clause": "A.8.2 – Privileged access rights",
        "nist_csf": "PR.AC-4 – Access permissions and authorisations are managed",
        "cyber_essentials": "Access Control – Admin account restrictions",
        "default_severity": "High",
        "source_systems": ["active_directory", "cloud_iam"],
    },
    {
        "control_id": "CM-004",
        "name": "Missing Security Patch",
        "description": "System running software with known CVE older than 30 days without patch",
        "category": "Vulnerability Management",
        "gdpr_clause": "Article 32(1)(d) – Regular testing and evaluation",
        "iso27001_clause": "A.8.8 – Management of technical vulnerabilities",
        "nist_csf": "PR.IP-12 – A vulnerability management plan is developed",
        "cyber_essentials": "Patch Management – Software updates within 14 days",
        "default_severity": "High",
        "source_systems": ["endpoint", "cloud_compute", "on_prem_server"],
    },
    {
        "control_id": "CM-005",
        "name": "Data Retention Policy Breach",
        "description": "Personal data retained beyond defined retention period without lawful basis",
        "category": "Data Governance",
        "gdpr_clause": "Article 5(1)(e) – Storage limitation principle",
        "iso27001_clause": "A.5.33 – Protection of records",
        "nist_csf": "PR.IP-6 – Data is destroyed according to policy",
        "cyber_essentials": "N/A – Not directly applicable",
        "default_severity": "Critical",
        "source_systems": ["file_server", "cloud_storage", "database"],
    },
    {
        "control_id": "CM-006",
        "name": "No Multi-Factor Authentication",
        "description": "User account accessing sensitive systems without MFA enabled",
        "category": "Access Control",
        "gdpr_clause": "Article 32 – Appropriate technical measures",
        "iso27001_clause": "A.8.5 – Secure authentication",
        "nist_csf": "PR.AC-7 – Authentication commensurate with risk",
        "cyber_essentials": "Access Control – Multi-factor authentication",
        "default_severity": "High",
        "source_systems": ["active_directory", "cloud_iam", "saas_applications"],
    },
    {
        "control_id": "CM-007",
        "name": "Audit Log Disabled or Tampered",
        "description": "Audit logging disabled or log records show signs of deletion/modification",
        "category": "Monitoring & Audit",
        "gdpr_clause": "Article 5(2) – Accountability principle",
        "iso27001_clause": "A.8.15 – Logging",
        "nist_csf": "DE.CM-3 – Personnel activity is monitored",
        "cyber_essentials": "N/A – Not directly in scope",
        "default_severity": "Critical",
        "source_systems": ["siem", "on_prem_server", "cloud_logging"],
    },
    {
        "control_id": "CM-008",
        "name": "Firewall Rule Misconfiguration",
        "description": "Inbound/outbound firewall rule allows unrestricted traffic on sensitive ports",
        "category": "Network Security",
        "gdpr_clause": "Article 32 – Technical security measures",
        "iso27001_clause": "A.8.20 – Networks security",
        "nist_csf": "PR.AC-5 – Network integrity is protected",
        "cyber_essentials": "Boundary Firewalls – Rules restrict unnecessary access",
        "default_severity": "Critical",
        "source_systems": ["firewall", "network_monitor"],
    },
    {
        "control_id": "CM-009",
        "name": "Personal Data Exfiltration Risk",
        "description": "Large volume of personal data transferred to external or unapproved destination",
        "category": "Data Protection",
        "gdpr_clause": "Article 44 – Transfers to third countries",
        "iso27001_clause": "A.5.14 – Information transfer",
        "nist_csf": "DE.CM-7 – Monitoring for unauthorised personnel/devices/software",
        "cyber_essentials": "N/A – Not directly in scope",
        "default_severity": "Critical",
        "source_systems": ["dlp", "firewall", "cloud_storage"],
    },
    {
        "control_id": "CM-010",
        "name": "Inactive Account Not Disabled",
        "description": "User account inactive for 90+ days still active in directory",
        "category": "Access Control",
        "gdpr_clause": "Article 5(1)(e) – Storage limitation / data minimisation",
        "iso27001_clause": "A.8.3 – Information access restriction",
        "nist_csf": "PR.AC-1 – Identities and credentials are managed",
        "cyber_essentials": "Access Control – Remove or disable unused accounts",
        "default_severity": "Medium",
        "source_systems": ["active_directory", "cloud_iam"],
    },
    {
        "control_id": "CM-011",
        "name": "Malware Detection Event",
        "description": "Endpoint protection detected malware; remediation not confirmed within SLA",
        "category": "Endpoint Security",
        "gdpr_clause": "Article 32(1)(b) – Ongoing confidentiality and integrity",
        "iso27001_clause": "A.8.7 – Protection against malware",
        "nist_csf": "DE.CM-4 – Malicious code is detected",
        "cyber_essentials": "Malware Protection – Anti-malware controls",
        "default_severity": "Critical",
        "source_systems": ["endpoint", "siem"],
    },
    {
        "control_id": "CM-012",
        "name": "Third-Party Vendor Risk",
        "description": "Vendor accessing systems without current signed DPA or security assessment",
        "category": "Supply Chain",
        "gdpr_clause": "Article 28 – Processor obligations and contracts",
        "iso27001_clause": "A.5.19 – Information security in supplier relationships",
        "nist_csf": "ID.SC-3 – Suppliers are assessed prior to contracting",
        "cyber_essentials": "N/A – Not directly in scope",
        "default_severity": "High",
        "source_systems": ["vendor_portal", "active_directory"],
    },
    {
        "control_id": "CM-013",
        "name": "Incident Response Delay",
        "description": "Security incident not escalated within defined SLA (4 hours for Critical)",
        "category": "Incident Management",
        "gdpr_clause": "Article 33 – Notification within 72 hours",
        "iso27001_clause": "A.5.26 – Response to information security incidents",
        "nist_csf": "RS.CO-2 – Incidents are reported per established criteria",
        "cyber_essentials": "N/A – Not directly in scope",
        "default_severity": "High",
        "source_systems": ["ticketing_system", "siem"],
    },
    {
        "control_id": "CM-014",
        "name": "Backup Failure",
        "description": "Scheduled backup job failed or last verified backup exceeds RPO threshold",
        "category": "Business Continuity",
        "gdpr_clause": "Article 32(1)(c) – Ability to restore availability",
        "iso27001_clause": "A.8.13 – Information backup",
        "nist_csf": "PR.IP-4 – Backups of information are conducted",
        "cyber_essentials": "N/A – Not directly in scope",
        "default_severity": "High",
        "source_systems": ["backup_system", "cloud_storage"],
    },
    {
        "control_id": "CM-015",
        "name": "Unmanaged Device on Network",
        "description": "Device connected to network not registered in asset inventory",
        "category": "Asset Management",
        "gdpr_clause": "Article 32 – Security of processing environments",
        "iso27001_clause": "A.5.9 – Inventory of information and other associated assets",
        "nist_csf": "ID.AM-1 – Physical devices and systems are inventoried",
        "cyber_essentials": "Boundary Firewalls – Prevent unauthorised connections",
        "default_severity": "Medium",
        "source_systems": ["network_monitor", "dhcp"],
    },
]


def get_all_controls():
    return CONTROL_MATRIX


def get_control_by_id(control_id: str):
    for c in CONTROL_MATRIX:
        if c["control_id"] == control_id:
            return c
    return None


def get_controls_by_category(category: str):
    return [c for c in CONTROL_MATRIX if c["category"] == category]


def get_categories():
    return sorted(list(set(c["category"] for c in CONTROL_MATRIX)))
