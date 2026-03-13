"""
compliance_monitor/modules/report_generator.py
-----------------------------------------------
Report Generator: Produces audit-grade PDF compliance reports
from processed violation data.

Author : Opoku Mensah (w25035430)
Version: 1.0.0
"""

import os
from datetime import datetime
from fpdf import FPDF

def _s(text: str) -> str:
    """Sanitise text for FPDF latin-1 encoding."""
    return (str(text)
            .replace("\u2013", "-").replace("\u2014", "--")
            .replace("\u2018", "'").replace("\u2019", "'")
            .replace("\u201c", '"').replace("\u201d", '"')
            .encode("latin-1", errors="replace").decode("latin-1"))

BRAND_BLUE = (31, 73, 125)
BRAND_DARK = (30, 30, 30)
CRITICAL_RED = (192, 0, 0)
HIGH_ORANGE = (197, 90, 17)
MEDIUM_YELLOW = (155, 118, 0)
LOW_GREEN = (55, 86, 35)
LIGHT_GREY = (245, 245, 245)
MID_GREY = (200, 200, 200)

SEVERITY_COLOURS = {
    "Critical": CRITICAL_RED,
    "High": HIGH_ORANGE,
    "Medium": MEDIUM_YELLOW,
    "Low": LOW_GREEN,
}


class CompliancePDF(FPDF):

    def header(self):
        self.set_fill_color(*BRAND_BLUE)
        self.rect(0, 0, 210, 18, "F")
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 11)
        self.set_y(5)
        self.cell(0, 8, "SME COMPLIANCE MONITOR - AUDIT REPORT", align="C")
        self.set_text_color(*BRAND_DARK)
        self.ln(14)

    def footer(self):
        self.set_y(-13)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(120, 120, 120)
        self.cell(0, 5, f"CONFIDENTIAL -- Generated {datetime.now().strftime('%d %b %Y %H:%M')} | Page {self.page_no()}", align="C")

    def section_title(self, title: str):
        self.ln(4)
        self.set_fill_color(*BRAND_BLUE)
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 10)
        self.cell(0, 8, f"  {title}", fill=True, ln=True)
        self.set_text_color(*BRAND_DARK)
        self.ln(2)

    def kv_row(self, key: str, value: str, fill: bool = False):
        if fill:
            self.set_fill_color(*LIGHT_GREY)
        else:
            self.set_fill_color(255, 255, 255)
        self.set_font("Helvetica", "B", 8)
        self.cell(50, 6, _s(key), border=0, fill=fill)
        self.set_font("Helvetica", "", 8)
        self.cell(0, 6, _s(str(value))[:120], border=0, fill=fill, ln=True)


def _severity_badge(pdf: CompliancePDF, severity: str, x: float, y: float):
    colour = SEVERITY_COLOURS.get(severity, (100, 100, 100))
    pdf.set_fill_color(*colour)
    pdf.set_text_color(255, 255, 255)
    pdf.set_xy(x, y)
    pdf.set_font("Helvetica", "B", 8)
    pdf.cell(22, 6, severity.upper(), fill=True, align="C")
    pdf.set_text_color(*BRAND_DARK)


def generate_report(violations: list, risk_summary: dict, posture_scores: dict, output_path: str) -> str:
    """
    Generate a full compliance audit PDF report.
    Returns the output file path.
    """
    pdf = CompliancePDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.set_margins(15, 22, 15)
    pdf.add_page()

    # ── Title Block ──────────────────────────────────────────────────────────
    pdf.set_font("Helvetica", "B", 18)
    pdf.set_text_color(*BRAND_BLUE)
    pdf.cell(0, 10, "Compliance Monitoring Report", ln=True, align="C")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(80, 80, 80)
    pdf.cell(0, 6, f"Report Generated: {datetime.now().strftime('%d %B %Y at %H:%M UTC')}", ln=True, align="C")
    pdf.cell(0, 6, "Classification: CONFIDENTIAL -- Internal Use Only", ln=True, align="C")
    pdf.ln(4)

    # ── Executive Risk Summary ────────────────────────────────────────────────
    pdf.section_title("1. EXECUTIVE RISK SUMMARY")

    col_w = 42
    labels = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "TOTAL"]
    values = [
        str(risk_summary.get("Critical", 0)),
        str(risk_summary.get("High", 0)),
        str(risk_summary.get("Medium", 0)),
        str(risk_summary.get("Low", 0)),
        str(risk_summary.get("Total", 0)),
    ]
    colours = [CRITICAL_RED, HIGH_ORANGE, MEDIUM_YELLOW, LOW_GREEN, BRAND_BLUE]

    for i, (lbl, val, col) in enumerate(zip(labels, values, colours)):
        pdf.set_fill_color(*col)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(col_w - 2, 6, lbl, fill=True, align="C")
        pdf.set_text_color(*BRAND_DARK)
        if i < len(labels) - 1:
            pdf.set_x(pdf.get_x())
    pdf.ln(7)
    pdf.set_font("Helvetica", "B", 14)
    for i, (val, col) in enumerate(zip(values, colours)):
        pdf.set_text_color(*col)
        pdf.cell(col_w - 2, 9, val, align="C")
    pdf.ln(12)
    pdf.set_text_color(*BRAND_DARK)

    # ── Framework Compliance Posture ─────────────────────────────────────────
    pdf.section_title("2. FRAMEWORK COMPLIANCE POSTURE")

    framework_labels = {
        "GDPR": "UK GDPR / DPA 2018",
        "ISO27001": "ISO/IEC 27001:2022",
        "NIST_CSF": "NIST CSF 2.0",
        "Cyber_Essentials": "Cyber Essentials (NCSC)",
    }

    for fw_key, fw_name in framework_labels.items():
        score = posture_scores.get(fw_key, 0)
        bar_width = int((score / 100) * 140)
        if score >= 70:
            bar_col = LOW_GREEN
        elif score >= 40:
            bar_col = MEDIUM_YELLOW
        else:
            bar_col = CRITICAL_RED

        pdf.set_font("Helvetica", "", 9)
        pdf.cell(55, 7, fw_name)
        pdf.set_fill_color(*MID_GREY)
        pdf.cell(140, 7, "", fill=True, border=0)
        pdf.set_xy(pdf.get_x() - 140, pdf.get_y())
        pdf.set_fill_color(*bar_col)
        if bar_width > 0:
            pdf.cell(bar_width, 7, "", fill=True)
        pdf.set_xy(70 + bar_width + 16, pdf.get_y())
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(*bar_col)
        pdf.cell(20, 7, f"{score}%")
        pdf.set_text_color(*BRAND_DARK)
        pdf.ln(8)

    pdf.ln(2)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 5, "Score reflects current open violation posture. Higher score = stronger compliance alignment.", ln=True)
    pdf.set_text_color(*BRAND_DARK)

    # ── Violation Detail Table ────────────────────────────────────────────────
    pdf.add_page()
    pdf.section_title("3. VIOLATION DETAIL TABLE")

    # Table header
    headers = ["SEV", "Control", "Category", "Host / User", "Source", "GDPR Ref"]
    widths = [20, 45, 32, 38, 25, 20]
    pdf.set_fill_color(*BRAND_BLUE)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 7)
    for h, w in zip(headers, widths):
        pdf.cell(w, 7, h, fill=True, align="C", border=1)
    pdf.ln()
    pdf.set_text_color(*BRAND_DARK)

    fill = False
    for v in violations[:40]:  # Limit to 40 for readability
        sev = v.get("severity", "Low")
        colour = SEVERITY_COLOURS.get(sev, (80, 80, 80))
        pdf.set_fill_color(*LIGHT_GREY if fill else (255, 255, 255))
        pdf.set_font("Helvetica", "B", 7)
        pdf.set_text_color(*colour)
        pdf.cell(widths[0], 6, sev, fill=True, align="C", border=1)
        pdf.set_text_color(*BRAND_DARK)
        pdf.set_font("Helvetica", "", 7)
        name = _s(v.get("control_name", ""))[:30]
        cat = _s(v.get("category", ""))[:20]
        host = _s(f"{v.get('hostname','')[:15]} / {v.get('user','')[:10]}")
        src = _s(v.get("source_system", ""))[:15]
        gdpr = _s(v.get("gdpr_clause", ""))[:18]
        pdf.cell(widths[1], 6, name, fill=True, border=1)
        pdf.cell(widths[2], 6, cat, fill=True, border=1)
        pdf.cell(widths[3], 6, host, fill=True, border=1)
        pdf.cell(widths[4], 6, src, fill=True, border=1)
        pdf.cell(widths[5], 6, gdpr[:18], fill=True, border=1)
        pdf.ln()
        fill = not fill

    if len(violations) > 40:
        pdf.set_font("Helvetica", "I", 8)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(0, 5, f"  ... {len(violations) - 40} additional violations not shown. Export full dataset from dashboard.", ln=True)
        pdf.set_text_color(*BRAND_DARK)

    # ── Top Critical Violations ───────────────────────────────────────────────
    pdf.add_page()
    pdf.section_title("4. CRITICAL VIOLATIONS -- DETAILED RECORDS")

    critical = [v for v in violations if v.get("severity") == "Critical"][:8]
    if not critical:
        pdf.set_font("Helvetica", "I", 9)
        pdf.cell(0, 6, "No Critical violations detected in current monitoring window.", ln=True)
    else:
        for i, v in enumerate(critical, 1):
            pdf.set_fill_color(*LIGHT_GREY)
            pdf.set_font("Helvetica", "B", 9)
            pdf.cell(0, 7, _s(f"  [{i}] {v['control_name']}  |  {v['control_id']}  |  {v['timestamp']}"), fill=True, ln=True)
            pdf.kv_row("Violation ID:", v.get("violation_id", "N/A"), fill=False)
            pdf.kv_row("Source System:", f"{v.get('source_system','')} ({v.get('source_tier','')})", fill=True)
            pdf.kv_row("Host / User:", f"{v.get('hostname','')} / {v.get('user','')}", fill=False)
            pdf.kv_row("Detail:", v.get("detail", ""), fill=True)
            pdf.kv_row("UK GDPR:", v.get("gdpr_clause", ""), fill=False)
            pdf.kv_row("ISO 27001:", v.get("iso27001_clause", ""), fill=True)
            pdf.kv_row("NIST CSF 2.0:", v.get("nist_csf", ""), fill=False)
            pdf.kv_row("Cyber Essentials:", v.get("cyber_essentials", ""), fill=True)
            pdf.kv_row("Remediation Owner:", v.get("remediation_owner", ""), fill=False)
            pdf.kv_row("SLA Deadline:", v.get("sla_deadline", ""), fill=True)
            pdf.kv_row("Escalated:", "YES -- Immediate action required" if v.get("escalation_required") else "No", fill=False)
            pdf.ln(4)

    # ── Remediation Recommendations ───────────────────────────────────────────
    pdf.add_page()
    pdf.section_title("5. REMEDIATION RECOMMENDATIONS")

    recommendations = [
        ("CM-001 – Unauthorised Access", "Deploy account lockout after 5 failed attempts. Review and enforce Kerberos pre-authentication. Enable SIEM alerting on brute force patterns (ISO 27001 A.8.3)."),
        ("CM-002 – Unencrypted Transmission", "Enforce TLS 1.2/1.3 for all data-in-transit. Block HTTP/FTP on the perimeter firewall for sensitive traffic flows. Review DLP policies (GDPR Art. 32)."),
        ("CM-003 – Excessive Privileges", "Implement Privileged Access Management (PAM). Enforce least privilege and Just-In-Time access. All admin assignments require change ticket (ISO A.8.2)."),
        ("CM-004 – Missing Patches", "Establish automated patching with a 14-day SLA for Critical CVEs per Cyber Essentials requirements. Use vulnerability scanner weekly scans."),
        ("CM-005 – Data Retention Breach", "Deploy automated retention enforcement aligned to documented schedules. Conduct quarterly data minimisation audit (GDPR Art. 5(1)(e))."),
        ("CM-006 – No MFA", "Mandate MFA for all cloud and remote-access accounts immediately. Use conditional access policies in Azure Entra ID."),
        ("CM-007 – Audit Log Issues", "Centralise logging to immutable SIEM. Set alert on log gaps > 15 minutes. Protect log integrity with WORM storage (ISO A.8.15)."),
        ("CM-008 – Firewall Misconfiguration", "Conduct immediate firewall rule review. Implement change management for all rule modifications. Block RDP/SSH from internet unless via VPN (Cyber Essentials)."),
    ]

    for title, rec in recommendations:
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(0, 6, _s(title), ln=True)
        pdf.set_font("Helvetica", "", 9)
        pdf.multi_cell(0, 5, _s(rec))
        pdf.ln(2)

    # ── Certification Block ───────────────────────────────────────────────────
    pdf.ln(6)
    pdf.set_fill_color(*LIGHT_GREY)
    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(0, 7, "  REPORT CERTIFICATION", fill=True, ln=True)
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(0, 6, f"  Report generated by: SME Compliance Monitor v1.0.0", ln=True)
    pdf.cell(0, 6, f"  Frameworks assessed: UK GDPR/DPA 2018 | ISO/IEC 27001:2022 | NIST CSF 2.0 | Cyber Essentials", ln=True)
    pdf.cell(0, 6, f"  Total violations assessed: {len(violations)}", ln=True)
    pdf.cell(0, 6, f"  Report timestamp: {datetime.now().strftime('%d %B %Y %H:%M UTC')}", ln=True)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    pdf.output(output_path)
    return output_path
