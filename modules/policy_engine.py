"""
compliance_monitor/modules/policy_engine.py
--------------------------------------------
Policy Engine: Evaluates ingested events against compliance control rules.
Produces structured violation records with framework cross-references.

Author : Opoku Mensah (w25035430)
Version: 1.0.0
"""

from .control_matrix import get_control_by_id


SEVERITY_WEIGHTS = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
}

# Severity override rules based on event-specific fields
SEVERITY_OVERRIDES = {
    "CM-004": lambda e: "Critical" if e.get("cvss_score", 0) >= 9.0 else "High",
    "CM-009": lambda e: "Critical" if e.get("data_size_mb", 0) > 10000 else "High",
    "CM-005": lambda e: "Critical" if e.get("record_count", 0) > 10000 else "High",
    "CM-011": lambda e: "Critical" if e.get("remediation_status") in ["Pending", "Failed"] else "High",
}


def evaluate_event(event: dict) -> dict:
    """
    Evaluate a single event against the control matrix.
    Returns a violation record with framework mapping and severity.
    """
    control_id = event.get("control_id")
    control = get_control_by_id(control_id)

    if not control:
        return None

    # Determine severity
    if control_id in SEVERITY_OVERRIDES:
        severity = SEVERITY_OVERRIDES[control_id](event)
    else:
        severity = control["default_severity"]

    violation = {
        "violation_id": f"VIO-{event['event_id']}",
        "event_id": event["event_id"],
        "timestamp": event["timestamp"],
        "control_id": control_id,
        "control_name": control["name"],
        "category": control["category"],
        "severity": severity,
        "severity_weight": SEVERITY_WEIGHTS.get(severity, 1),
        "source_system": event["source_system"],
        "source_tier": event["source_tier"],
        "hostname": event.get("hostname", "N/A"),
        "user": event.get("user", "N/A"),
        "detail": event.get("detail", ""),
        "gdpr_clause": control["gdpr_clause"],
        "iso27001_clause": control["iso27001_clause"],
        "nist_csf": control["nist_csf"],
        "cyber_essentials": control["cyber_essentials"],
        "status": "Open",
        "raw_event": event,
    }

    return violation


def evaluate_all_events(events: list) -> list:
    """
    Evaluate a list of events and return all violation records.
    Filters out None results (unrecognised control IDs).
    """
    violations = []
    for event in events:
        v = evaluate_event(event)
        if v:
            violations.append(v)
    return violations


def compute_compliance_posture(violations: list) -> dict:
    """
    Compute per-framework compliance posture scores.
    Score = 100 - ((weighted_violations / max_possible) * 100), floored at 0.
    """
    frameworks = ["GDPR", "ISO27001", "NIST_CSF", "Cyber_Essentials"]
    max_weight = sum(SEVERITY_WEIGHTS.values()) * len(violations) if violations else 1

    framework_scores = {}
    for fw in frameworks:
        total_weight = 0
        for v in violations:
            if fw == "GDPR" and "N/A" not in v["gdpr_clause"]:
                total_weight += v["severity_weight"]
            elif fw == "ISO27001" and "N/A" not in v["iso27001_clause"]:
                total_weight += v["severity_weight"]
            elif fw == "NIST_CSF" and "N/A" not in v["nist_csf"]:
                total_weight += v["severity_weight"]
            elif fw == "Cyber_Essentials" and "N/A" not in v["cyber_essentials"]:
                total_weight += v["severity_weight"]

        # Normalise to 0-100 score, higher = better posture
        max_fw = max(1, max_weight)
        score = max(0, round(100 - ((total_weight / max_fw) * 100), 1))
        framework_scores[fw] = score

    return framework_scores


def get_risk_summary(violations: list) -> dict:
    summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Total": len(violations)}
    for v in violations:
        s = v.get("severity", "Low")
        summary[s] = summary.get(s, 0) + 1
    return summary
