"""
compliance_monitor/modules/alert_manager.py
--------------------------------------------
Alert Manager: Deduplicates violations, assigns triage status,
and manages escalation thresholds per severity SLA.

Author : Opoku Mensah (w25035430)
Version: 1.0.0
"""

from datetime import datetime, timedelta
import hashlib

# SLA thresholds in hours for escalation
ESCALATION_SLA = {
    "Critical": 4,
    "High": 24,
    "Medium": 72,
    "Low": 168,
}

REMEDIATION_OWNER = {
    "Access Control": "IT Security Team",
    "Data Protection": "Data Protection Officer",
    "Vulnerability Management": "IT Operations",
    "Data Governance": "Data Protection Officer",
    "Monitoring & Audit": "IT Security Team",
    "Network Security": "Network Team",
    "Endpoint Security": "IT Operations",
    "Supply Chain": "Compliance Officer",
    "Incident Management": "IT Security Team",
    "Business Continuity": "IT Operations",
    "Asset Management": "IT Operations",
}


def _fingerprint(violation: dict) -> str:
    """Create a deduplication hash from control_id + hostname + user."""
    key = f"{violation['control_id']}:{violation['hostname']}:{violation['user']}"
    return hashlib.md5(key.encode()).hexdigest()[:12]


def deduplicate(violations: list) -> list:
    """
    Remove duplicate violations with same control, host, user within 24-hour window.
    Keeps the most recent occurrence.
    """
    seen = {}
    for v in sorted(violations, key=lambda x: x["timestamp"], reverse=True):
        fp = _fingerprint(v)
        if fp not in seen:
            seen[fp] = v
    return list(seen.values())


def triage_violations(violations: list) -> list:
    """
    Enrich each violation with:
      - escalation_required flag
      - remediation_owner
      - sla_deadline
      - alert_colour (for UI display)
    """
    now = datetime.now()
    colour_map = {
        "Critical": "#FF3B30",
        "High": "#FF9500",
        "Medium": "#FFCC00",
        "Low": "#34C759",
    }

    triaged = []
    for v in violations:
        severity = v.get("severity", "Low")
        sla_hours = ESCALATION_SLA.get(severity, 168)

        try:
            event_time = datetime.strptime(v["timestamp"], "%Y-%m-%d %H:%M:%S")
        except Exception:
            event_time = now

        sla_deadline = event_time + timedelta(hours=sla_hours)
        escalation_required = now > sla_deadline

        v["sla_hours"] = sla_hours
        v["sla_deadline"] = sla_deadline.strftime("%Y-%m-%d %H:%M:%S")
        v["escalation_required"] = escalation_required
        v["remediation_owner"] = REMEDIATION_OWNER.get(v.get("category", ""), "IT Security Team")
        v["alert_colour"] = colour_map.get(severity, "#8E8E93")
        v["status"] = "Escalated" if escalation_required else "Open"

        triaged.append(v)

    # Sort: Critical first, then High, then by timestamp
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    triaged.sort(key=lambda x: (severity_order.get(x["severity"], 9), x["timestamp"]))

    return triaged


def get_escalated(violations: list) -> list:
    return [v for v in violations if v.get("escalation_required", False)]


def get_open(violations: list) -> list:
    return [v for v in violations if not v.get("escalation_required", False)]


def process_alerts(violations: list) -> list:
    """Full pipeline: deduplicate → triage → return."""
    deduped = deduplicate(violations)
    triaged = triage_violations(deduped)
    return triaged
