"""
SME Compliance Monitor — Email Alerting Module
-----------------------------------------------
Sends automated email alerts when Critical or High violations
are detected. Uses Gmail SMTP (no API key required).

Setup:
  1. Enable 2-Factor Authentication on your Gmail account
  2. Go to Google Account -> Security -> App Passwords
  3. Generate an App Password for "Mail"
  4. Add it to Streamlit secrets or environment variable

Author : Opoku Mensah
Version: 2.1.0
"""

import smtplib
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime

# ── Sender Configuration ──────────────────────────────────────────────────────
SENDER_EMAIL    = "actionom@gmail.com"
SENDER_NAME     = "Opoku Mensah | SME Compliance Monitor"
CONTACT_PHONE   = "+44 7440 135240"
PRODUCT_NAME    = "SME Compliance Monitor"

# Gmail App Password — stored in Streamlit secrets or environment variable
# In Streamlit Cloud: Settings -> Secrets -> add GMAIL_APP_PASSWORD = "xxxx xxxx xxxx xxxx"
# Locally: set environment variable GMAIL_APP_PASSWORD
def _get_app_password() -> str:
    try:
        import streamlit as st
        return st.secrets.get("GMAIL_APP_PASSWORD", os.environ.get("GMAIL_APP_PASSWORD", ""))
    except Exception:
        return os.environ.get("GMAIL_APP_PASSWORD", "")


# ── Email Templates ───────────────────────────────────────────────────────────

def _build_alert_html(violations: list, client_name: str, risk_summary: dict,
                       posture_scores: dict) -> str:
    """Build the HTML body for the alert email."""

    critical_count = risk_summary.get("Critical", 0)
    high_count     = risk_summary.get("High", 0)
    total_count    = risk_summary.get("Total", 0)

    # Colour for overall status
    if critical_count > 0:
        status_colour = "#C00000"
        status_text   = "CRITICAL — Immediate Action Required"
    elif high_count > 0:
        status_colour = "#C55A11"
        status_text   = "HIGH RISK — Action Required Within 24 Hours"
    else:
        status_colour = "#375623"
        status_text   = "MEDIUM RISK — Action Required Within 72 Hours"

    # Top violations table rows
    top_violations = violations[:8]
    violation_rows = ""
    sev_colours = {
        "Critical": "#C00000", "High": "#C55A11",
        "Medium": "#9B7600", "Low": "#375623"
    }
    for v in top_violations:
        sc = sev_colours.get(v.get("severity","Low"), "#333")
        violation_rows += f"""
        <tr style="border-bottom:1px solid #eee;">
            <td style="padding:8px;font-weight:bold;color:{sc};">{v.get('severity','')}</td>
            <td style="padding:8px;">{v.get('control_id','')}</td>
            <td style="padding:8px;">{v.get('control_name','')}</td>
            <td style="padding:8px;color:#666;">{v.get('hostname','')}</td>
            <td style="padding:8px;color:#888;font-size:12px;">{v.get('gdpr_clause','')[:35]}</td>
        </tr>"""

    # Framework posture bars
    fw_rows = ""
    fw_map = {
        "GDPR": "UK GDPR / DPA 2018",
        "ISO27001": "ISO/IEC 27001:2022",
        "NIST_CSF": "NIST CSF 2.0",
        "Cyber_Essentials": "Cyber Essentials (NCSC)"
    }
    for key, name in fw_map.items():
        score = posture_scores.get(key, 0)
        bar_c = "#375623" if score >= 70 else "#C55A11" if score >= 40 else "#C00000"
        fw_rows += f"""
        <tr>
            <td style="padding:6px 8px;font-size:13px;">{name}</td>
            <td style="padding:6px 8px;">
                <div style="background:#eee;border-radius:4px;height:12px;width:200px;">
                    <div style="background:{bar_c};width:{score}%;height:100%;border-radius:4px;"></div>
                </div>
            </td>
            <td style="padding:6px 8px;font-weight:bold;color:{bar_c};">{score}%</td>
        </tr>"""

    client_str = f" — {client_name}" if client_name else ""
    now_str = datetime.now().strftime("%d %B %Y at %H:%M UTC")

    html = f"""
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f4f4f4;font-family:Arial,sans-serif;">

<table width="100%" cellpadding="0" cellspacing="0" bgcolor="#f4f4f4">
<tr><td align="center" style="padding:30px 0;">

  <!-- Card -->
  <table width="620" cellpadding="0" cellspacing="0"
         style="background:white;border-radius:12px;overflow:hidden;
                box-shadow:0 4px 20px rgba(0,0,0,0.1);">

    <!-- Header -->
    <tr>
      <td style="background:linear-gradient(135deg,#1F497D,#2E75B6);
                 padding:28px 32px;text-align:center;">
        <div style="font-size:32px;margin-bottom:8px;">🛡️</div>
        <h1 style="margin:0;color:white;font-size:22px;">{PRODUCT_NAME}</h1>
        <p style="margin:6px 0 0;color:#BDD7EE;font-size:13px;">
          Automated Compliance Alert{client_str}
        </p>
      </td>
    </tr>

    <!-- Status Banner -->
    <tr>
      <td style="background:{status_colour};padding:14px 32px;text-align:center;">
        <strong style="color:white;font-size:15px;">🚨 {status_text}</strong>
      </td>
    </tr>

    <!-- Summary Stats -->
    <tr>
      <td style="padding:24px 32px;">
        <h2 style="color:#1F497D;margin:0 0 16px;font-size:16px;
                   border-bottom:2px solid #1F497D;padding-bottom:8px;">
          Executive Risk Summary
        </h2>
        <table width="100%" cellpadding="0" cellspacing="8">
          <tr>
            <td align="center" style="background:#FFE5E5;border-radius:8px;
                padding:16px;border-left:4px solid #C00000;">
              <div style="font-size:32px;font-weight:bold;color:#C00000;">
                {critical_count}
              </div>
              <div style="color:#666;font-size:12px;margin-top:4px;">CRITICAL</div>
            </td>
            <td width="12"></td>
            <td align="center" style="background:#FFF3E0;border-radius:8px;
                padding:16px;border-left:4px solid #C55A11;">
              <div style="font-size:32px;font-weight:bold;color:#C55A11;">
                {high_count}
              </div>
              <div style="color:#666;font-size:12px;margin-top:4px;">HIGH</div>
            </td>
            <td width="12"></td>
            <td align="center" style="background:#FFFDE7;border-radius:8px;
                padding:16px;border-left:4px solid #9B7600;">
              <div style="font-size:32px;font-weight:bold;color:#9B7600;">
                {risk_summary.get("Medium",0)}
              </div>
              <div style="color:#666;font-size:12px;margin-top:4px;">MEDIUM</div>
            </td>
            <td width="12"></td>
            <td align="center" style="background:#E3F0FF;border-radius:8px;
                padding:16px;border-left:4px solid #1F497D;">
              <div style="font-size:32px;font-weight:bold;color:#1F497D;">
                {total_count}
              </div>
              <div style="color:#666;font-size:12px;margin-top:4px;">TOTAL</div>
            </td>
          </tr>
        </table>
      </td>
    </tr>

    <!-- Framework Posture -->
    <tr>
      <td style="padding:0 32px 24px;">
        <h2 style="color:#1F497D;margin:0 0 16px;font-size:16px;
                   border-bottom:2px solid #1F497D;padding-bottom:8px;">
          Framework Compliance Posture
        </h2>
        <table width="100%" cellpadding="0" cellspacing="0">
          {fw_rows}
        </table>
      </td>
    </tr>

    <!-- Top Violations -->
    <tr>
      <td style="padding:0 32px 24px;">
        <h2 style="color:#1F497D;margin:0 0 16px;font-size:16px;
                   border-bottom:2px solid #1F497D;padding-bottom:8px;">
          Top Violations Requiring Attention
        </h2>
        <table width="100%" cellpadding="0" cellspacing="0"
               style="border-collapse:collapse;font-size:13px;">
          <tr style="background:#1F497D;color:white;">
            <th style="padding:8px;text-align:left;">Severity</th>
            <th style="padding:8px;text-align:left;">Control</th>
            <th style="padding:8px;text-align:left;">Violation</th>
            <th style="padding:8px;text-align:left;">Host</th>
            <th style="padding:8px;text-align:left;">GDPR Ref</th>
          </tr>
          {violation_rows}
        </table>
        {"<p style='color:#888;font-size:12px;margin-top:8px;'>... and " + str(total_count - 8) + " additional violations. Login to view all.</p>" if total_count > 8 else ""}
      </td>
    </tr>

    <!-- CTA Button -->
    <tr>
      <td style="padding:0 32px 32px;text-align:center;">
        <a href="https://sme-compliance-monitor.streamlit.app"
           style="background:linear-gradient(135deg,#1F497D,#2E75B6);
                  color:white;text-decoration:none;padding:14px 36px;
                  border-radius:8px;font-weight:bold;font-size:15px;
                  display:inline-block;">
          🔐 Login to Full Dashboard
        </a>
      </td>
    </tr>

    <!-- Footer -->
    <tr>
      <td style="background:#F8F9FA;padding:20px 32px;
                 border-top:1px solid #eee;text-align:center;">
        <p style="margin:0;color:#666;font-size:12px;">
          This alert was generated automatically by {PRODUCT_NAME}<br>
          Report generated: {now_str}<br><br>
          <strong>{SENDER_NAME}</strong><br>
          📧 {SENDER_EMAIL} &nbsp;|&nbsp; 📞 {CONTACT_PHONE}<br><br>
          <span style="color:#aaa;font-size:11px;">
            Classification: CONFIDENTIAL — For authorised recipients only
          </span>
        </p>
      </td>
    </tr>

  </table>
</td></tr>
</table>
</body>
</html>"""
    return html


# ── Send Functions ────────────────────────────────────────────────────────────

def send_alert_email(recipient_email: str, client_name: str,
                     violations: list, risk_summary: dict,
                     posture_scores: dict) -> dict:
    """
    Send a compliance alert email to the specified recipient.
    Returns dict with success status and message.
    """
    app_password = _get_app_password()
    if not app_password:
        return {
            "success": False,
            "message": "Gmail App Password not configured. Add GMAIL_APP_PASSWORD to Streamlit secrets."
        }

    critical = risk_summary.get("Critical", 0)
    high     = risk_summary.get("High", 0)
    total    = risk_summary.get("Total", 0)
    client_str = f" — {client_name}" if client_name else ""

    if critical > 0:
        subject = f"🚨 CRITICAL ALERT: {critical} Critical Violations Detected{client_str}"
    elif high > 0:
        subject = f"⚠️ HIGH RISK ALERT: {high} High Violations Detected{client_str}"
    else:
        subject = f"📋 Compliance Alert: {total} Violations Detected{client_str}"

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = f"{SENDER_NAME} <{SENDER_EMAIL}>"
        msg["To"]      = recipient_email

        # Plain text fallback
        text_body = f"""
SME Compliance Monitor — Automated Alert{client_str}
{'='*50}
Generated: {datetime.now().strftime('%d %B %Y at %H:%M UTC')}

RISK SUMMARY
Critical: {critical}
High:     {high}
Medium:   {risk_summary.get('Medium', 0)}
Total:    {total}

FRAMEWORK POSTURE
UK GDPR / DPA 2018:    {posture_scores.get('GDPR', 0)}%
ISO/IEC 27001:2022:    {posture_scores.get('ISO27001', 0)}%
NIST CSF 2.0:          {posture_scores.get('NIST_CSF', 0)}%
Cyber Essentials:      {posture_scores.get('Cyber_Essentials', 0)}%

Login to full dashboard: https://sme-compliance-monitor.streamlit.app

{SENDER_NAME}
{SENDER_EMAIL} | {CONTACT_PHONE}
        """

        html_body = _build_alert_html(violations, client_name, risk_summary, posture_scores)

        msg.attach(MIMEText(text_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(SENDER_EMAIL, app_password)
            server.sendmail(SENDER_EMAIL, recipient_email, msg.as_string())

        return {
            "success": True,
            "message": f"Alert email sent successfully to {recipient_email}"
        }

    except smtplib.SMTPAuthenticationError:
        return {
            "success": False,
            "message": "Gmail authentication failed. Check your App Password in Streamlit secrets."
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Email error: {str(e)}"
        }


def send_test_email(recipient_email: str) -> dict:
    """Send a test email to verify configuration is working."""
    app_password = _get_app_password()
    if not app_password:
        return {
            "success": False,
            "message": "Gmail App Password not configured."
        }
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "✅ SME Compliance Monitor — Email Test Successful"
        msg["From"]    = f"{SENDER_NAME} <{SENDER_EMAIL}>"
        msg["To"]      = recipient_email

        html = f"""
        <div style="font-family:Arial;max-width:500px;margin:auto;
                    padding:32px;background:#F0F7FF;border-radius:12px;">
            <h2 style="color:#1F497D;">✅ Email Alerts Configured Successfully</h2>
            <p>Your SME Compliance Monitor email alerting system is working correctly.</p>
            <p>You will now receive automatic alerts when:</p>
            <ul>
                <li>Critical violations are detected</li>
                <li>SLA deadlines are breached</li>
                <li>Framework posture drops below threshold</li>
            </ul>
            <hr style="border:1px solid #BDD7EE;">
            <p style="color:#666;font-size:12px;">
                {SENDER_NAME}<br>
                {SENDER_EMAIL} | {CONTACT_PHONE}
            </p>
        </div>"""

        msg.attach(MIMEText(html, "html"))

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(SENDER_EMAIL, app_password)
            server.sendmail(SENDER_EMAIL, recipient_email, msg.as_string())

        return {"success": True, "message": f"Test email sent to {recipient_email}"}
    except Exception as e:
        return {"success": False, "message": str(e)}


def is_email_configured() -> bool:
    """Check whether email alerting is ready to use."""
    return bool(_get_app_password())
