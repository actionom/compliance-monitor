"""
compliance_monitor/app.py
--------------------------
SME Compliance Monitor — Streamlit Dashboard
Flags risks and policy violations across hybrid on-prem and cloud systems.
Aligned to: UK GDPR/DPA 2018 | ISO 27001:2022 | NIST CSF 2.0 | Cyber Essentials

Author : Opoku Mensah (w25035430)
Version: 1.0.0
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime

from modules.data_collector import collect_all_events, SOURCE_SYSTEMS
from modules.policy_engine import evaluate_all_events, compute_compliance_posture, get_risk_summary
from modules.alert_manager import process_alerts, get_escalated
from modules.report_generator import generate_report
from modules.control_matrix import get_categories, get_all_controls

# ── Page Configuration ────────────────────────────────────────────────────────
st.set_page_config(
    page_title="SME Compliance Monitor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    .main { background-color: #f8f9fa; }
    .metric-card {
        background: white;
        border-radius: 8px;
        padding: 16px;
        border-left: 5px solid;
        box-shadow: 0 2px 4px rgba(0,0,0,0.08);
    }
    .critical { border-left-color: #FF3B30; }
    .high     { border-left-color: #FF9500; }
    .medium   { border-left-color: #FFCC00; }
    .low      { border-left-color: #34C759; }
    .escalated-banner {
        background: #FF3B30;
        color: white;
        padding: 10px 16px;
        border-radius: 6px;
        font-weight: bold;
        margin-bottom: 12px;
    }
    .header-brand {
        background: linear-gradient(135deg, #1F497D 0%, #2E75B6 100%);
        color: white;
        padding: 20px 24px;
        border-radius: 10px;
        margin-bottom: 20px;
    }
    .framework-badge {
        display: inline-block;
        padding: 3px 10px;
        border-radius: 12px;
        font-size: 11px;
        font-weight: bold;
        margin: 2px;
        color: white;
    }
    div[data-testid="stDataFrame"] { border-radius: 8px; }
    .stSelectbox label, .stMultiSelect label { font-weight: 600; }
</style>
""", unsafe_allow_html=True)

# ── Session State Initialisation ──────────────────────────────────────────────
if "violations" not in st.session_state:
    st.session_state.violations = []
if "last_refresh" not in st.session_state:
    st.session_state.last_refresh = None
if "report_path" not in st.session_state:
    st.session_state.report_path = None


def load_data(events_per_control: int = 4):
    events = collect_all_events(events_per_control=events_per_control)
    violations = evaluate_all_events(events)
    processed = process_alerts(violations)
    st.session_state.violations = processed
    st.session_state.last_refresh = datetime.now().strftime("%d %b %Y %H:%M:%S")


# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.image("https://upload.wikimedia.org/wikipedia/commons/thumb/a/a7/Camponotus_flavomarginatus_ant.jpg/1px-solid.png",
             width=1)  # spacer
    st.markdown("""
    <div style='text-align:center; padding: 10px 0;'>
        <h3 style='color:#1F497D; margin:0;'>🛡️ SME Compliance Monitor</h3>
        <p style='color:#666; font-size:12px; margin:4px 0;'>v1.0.0 | Opoku Mensah (w25035430)</p>
    </div>
    """, unsafe_allow_html=True)
    st.divider()

    st.subheader("⚙️ Data Controls")
    events_per_control = st.slider("Events per Control Rule", min_value=1, max_value=8, value=4)

    if st.button("🔄 Refresh / Simulate New Data", use_container_width=True, type="primary"):
        with st.spinner("Ingesting logs from hybrid sources..."):
            load_data(events_per_control)
        st.success("Data refreshed successfully.")

    st.divider()
    st.subheader("🔍 Filters")

    severity_filter = st.multiselect(
        "Severity",
        ["Critical", "High", "Medium", "Low"],
        default=["Critical", "High", "Medium", "Low"],
    )

    category_filter = st.multiselect(
        "Category",
        get_categories(),
        default=get_categories(),
    )

    tier_filter = st.multiselect(
        "Deployment Tier",
        ["On-Premises", "Cloud", "Hybrid"],
        default=["On-Premises", "Cloud", "Hybrid"],
    )

    framework_filter = st.selectbox(
        "Framework Focus",
        ["All", "UK GDPR / DPA 2018", "ISO 27001:2022", "NIST CSF 2.0", "Cyber Essentials"],
    )

    st.divider()
    st.subheader("📋 Compliance Frameworks")
    for fw in ["UK GDPR / DPA 2018", "ISO 27001:2022", "NIST CSF 2.0", "Cyber Essentials (NCSC)"]:
        st.markdown(f"✅ {fw}")

    if st.session_state.last_refresh:
        st.caption(f"Last refresh: {st.session_state.last_refresh}")

# ── Auto-load on first run ────────────────────────────────────────────────────
if not st.session_state.violations:
    with st.spinner("Initialising — ingesting simulated SME log data..."):
        load_data(events_per_control)

# ── Apply Filters ─────────────────────────────────────────────────────────────
all_violations = st.session_state.violations
filtered = [
    v for v in all_violations
    if v.get("severity") in severity_filter
    and v.get("category") in category_filter
    and v.get("source_tier") in tier_filter
]

# ── Header Banner ─────────────────────────────────────────────────────────────
st.markdown("""
<div class='header-brand'>
    <h2 style='margin:0; color:white;'>🛡️ SME Compliance Monitor</h2>
    <p style='margin:4px 0 0 0; color:#BDD7EE; font-size:14px;'>
        Real-time policy violation detection across hybrid infrastructure &nbsp;|&nbsp;
        UK GDPR &nbsp;·&nbsp; ISO 27001:2022 &nbsp;·&nbsp; NIST CSF 2.0 &nbsp;·&nbsp; Cyber Essentials
    </p>
</div>
""", unsafe_allow_html=True)

# ── Escalation Banner ─────────────────────────────────────────────────────────
escalated = get_escalated(filtered)
if escalated:
    st.markdown(f"""
    <div class='escalated-banner'>
        🚨 ESCALATION ALERT — {len(escalated)} violation(s) have breached their SLA and require IMMEDIATE attention.
    </div>
    """, unsafe_allow_html=True)

# ── KPI Metrics ───────────────────────────────────────────────────────────────
risk_summary = get_risk_summary(filtered)
c1, c2, c3, c4, c5 = st.columns(5)
kpi_data = [
    (c1, "🔴 Critical", risk_summary["Critical"], "critical"),
    (c2, "🟠 High", risk_summary["High"], "high"),
    (c3, "🟡 Medium", risk_summary["Medium"], "medium"),
    (c4, "🟢 Low", risk_summary["Low"], "low"),
    (c5, "📊 Total", risk_summary["Total"], "critical" if risk_summary["Critical"] > 0 else "low"),
]
for col, label, val, css_cls in kpi_data:
    with col:
        st.markdown(f"""
        <div class='metric-card {css_cls}'>
            <div style='font-size:13px; color:#666;'>{label}</div>
            <div style='font-size:36px; font-weight:bold; color:#1F497D;'>{val}</div>
        </div>
        """, unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# ── Charts Row 1 ──────────────────────────────────────────────────────────────
col_left, col_right = st.columns([1, 1])

with col_left:
    st.subheader("📊 Violations by Category")
    if filtered:
        cat_counts = pd.Series([v["category"] for v in filtered]).value_counts().reset_index()
        cat_counts.columns = ["Category", "Count"]
        fig = px.bar(
            cat_counts, x="Count", y="Category", orientation="h",
            color="Count", color_continuous_scale=["#34C759", "#FFCC00", "#FF9500", "#FF3B30"],
            template="plotly_white",
        )
        fig.update_layout(height=320, margin=dict(l=0, r=0, t=10, b=0), coloraxis_showscale=False)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No data to display.")

with col_right:
    st.subheader("🍩 Severity Distribution")
    if filtered:
        sev_counts = pd.Series([v["severity"] for v in filtered]).value_counts()
        sev_colours = {"Critical": "#FF3B30", "High": "#FF9500", "Medium": "#FFCC00", "Low": "#34C759"}
        fig2 = go.Figure(go.Pie(
            labels=sev_counts.index.tolist(),
            values=sev_counts.values.tolist(),
            hole=0.5,
            marker_colors=[sev_colours.get(s, "#ccc") for s in sev_counts.index],
        ))
        fig2.update_layout(height=320, margin=dict(l=0, r=0, t=10, b=0),
                           legend=dict(orientation="h", yanchor="bottom", y=-0.2))
        st.plotly_chart(fig2, use_container_width=True)

# ── Framework Compliance Posture ──────────────────────────────────────────────
st.subheader("🎯 Framework Compliance Posture")
posture = compute_compliance_posture(filtered)

fw_labels = {
    "GDPR": "UK GDPR / DPA 2018",
    "ISO27001": "ISO/IEC 27001:2022",
    "NIST_CSF": "NIST CSF 2.0",
    "Cyber_Essentials": "Cyber Essentials (NCSC)",
}

cols = st.columns(4)
for col, (fw_key, fw_name) in zip(cols, fw_labels.items()):
    score = posture.get(fw_key, 0)
    colour = "#34C759" if score >= 70 else "#FF9500" if score >= 40 else "#FF3B30"
    with col:
        st.markdown(f"""
        <div style='background:white; border-radius:8px; padding:14px; box-shadow:0 2px 4px rgba(0,0,0,0.08); text-align:center;'>
            <div style='font-size:11px; color:#666; font-weight:600;'>{fw_name}</div>
            <div style='font-size:40px; font-weight:bold; color:{colour};'>{score}%</div>
            <div style='background:#eee; border-radius:4px; height:8px; margin-top:6px;'>
                <div style='background:{colour}; width:{score}%; height:100%; border-radius:4px;'></div>
            </div>
        </div>
        """, unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# ── Deployment Tier Chart ─────────────────────────────────────────────────────
col_tier, col_trend = st.columns([1, 1])

with col_tier:
    st.subheader("🏗️ Violations by Deployment Tier")
    if filtered:
        tier_counts = pd.Series([v["source_tier"] for v in filtered]).value_counts().reset_index()
        tier_counts.columns = ["Tier", "Count"]
        tier_colours = {"On-Premises": "#1F497D", "Cloud": "#2E75B6", "Hybrid": "#9DC3E6"}
        fig3 = px.pie(tier_counts, values="Count", names="Tier",
                      color="Tier", color_discrete_map=tier_colours,
                      template="plotly_white")
        fig3.update_layout(height=280, margin=dict(l=0, r=0, t=10, b=0))
        st.plotly_chart(fig3, use_container_width=True)

with col_trend:
    st.subheader("📈 Violations by Control ID")
    if filtered:
        ctrl_counts = pd.Series([v["control_id"] for v in filtered]).value_counts().head(10).reset_index()
        ctrl_counts.columns = ["Control", "Count"]
        fig4 = px.bar(ctrl_counts, x="Control", y="Count",
                      color="Count",
                      color_continuous_scale=["#BDD7EE", "#FF3B30"],
                      template="plotly_white")
        fig4.update_layout(height=280, margin=dict(l=0, r=0, t=10, b=0),
                           coloraxis_showscale=False)
        st.plotly_chart(fig4, use_container_width=True)

# ── Violation Feed Table ──────────────────────────────────────────────────────
st.subheader("📋 Live Violation Feed")

if filtered:
    df = pd.DataFrame([{
        "Severity": v["severity"],
        "Control ID": v["control_id"],
        "Violation": v["control_name"],
        "Category": v["category"],
        "Host": v["hostname"],
        "User": v["user"],
        "Source": v["source_system"],
        "Tier": v["source_tier"],
        "GDPR Ref": v["gdpr_clause"][:40],
        "ISO 27001": v["iso27001_clause"][:35],
        "NIST CSF": v["nist_csf"][:40],
        "Timestamp": v["timestamp"],
        "SLA Deadline": v["sla_deadline"],
        "Escalated": "🚨 YES" if v.get("escalation_required") else "✅ No",
        "Owner": v.get("remediation_owner", ""),
        "Detail": v.get("detail", ""),
    } for v in filtered])

    # Colour-code severity
    def colour_severity(val):
        colours = {
            "Critical": "background-color: #FFE5E5; color: #C00000; font-weight: bold;",
            "High": "background-color: #FFF3E0; color: #C56011; font-weight: bold;",
            "Medium": "background-color: #FFFDE7; color: #9B7600;",
            "Low": "background-color: #E8F5E9; color: #376023;",
        }
        return colours.get(val, "")

    styled_df = df.style.applymap(colour_severity, subset=["Severity"])
    st.dataframe(styled_df, use_container_width=True, height=420)

    # CSV Download
    csv = df.to_csv(index=False)
    st.download_button(
        label="⬇️ Download Violation Dataset (CSV)",
        data=csv,
        file_name=f"compliance_violations_{datetime.now().strftime('%Y%m%d_%H%M')}.csv",
        mime="text/csv",
    )
else:
    st.success("✅ No violations match current filter criteria.")

# ── Escalated Violations Detail ───────────────────────────────────────────────
if escalated:
    with st.expander(f"🚨 Escalated Violations Requiring Immediate Action ({len(escalated)})", expanded=True):
        for v in escalated[:10]:
            sev = v.get("severity", "")
            sev_colours = {"Critical": "#FF3B30", "High": "#FF9500", "Medium": "#FFCC00"}
            col = sev_colours.get(sev, "#666")
            st.markdown(f"""
            <div style='border-left: 5px solid {col}; background: #fff8f8; padding:10px 14px; margin:6px 0; border-radius:4px;'>
                <strong style='color:{col};'>[{sev}] {v['control_name']}</strong> &nbsp;|&nbsp;
                <span style='color:#555;'>{v['control_id']}</span> &nbsp;|&nbsp;
                <span style='color:#888; font-size:12px;'>{v['timestamp']}</span><br>
                <span style='font-size:13px;'>{v.get('detail', '')}</span><br>
                <span style='font-size:12px; color:#1F497D;'>
                    👤 {v['user']} &nbsp;|&nbsp; 🖥️ {v['hostname']} &nbsp;|&nbsp; 
                    🗓️ SLA: {v['sla_deadline']} &nbsp;|&nbsp; 👷 {v['remediation_owner']}
                </span>
            </div>
            """, unsafe_allow_html=True)

# ── Control Matrix Reference ──────────────────────────────────────────────────
with st.expander("📖 Compliance Control Matrix Reference"):
    controls = get_all_controls()
    ctrl_df = pd.DataFrame([{
        "ID": c["control_id"],
        "Control Name": c["name"],
        "Category": c["category"],
        "Default Severity": c["default_severity"],
        "UK GDPR": c["gdpr_clause"],
        "ISO 27001": c["iso27001_clause"],
        "NIST CSF": c["nist_csf"],
        "Cyber Essentials": c["cyber_essentials"],
    } for c in controls])
    st.dataframe(ctrl_df, use_container_width=True, height=350)

# ── PDF Report Generation ─────────────────────────────────────────────────────
st.subheader("📄 Audit Report Generation")
col_gen, col_dl = st.columns([2, 1])

with col_gen:
    if st.button("🖨️ Generate PDF Compliance Audit Report", use_container_width=True, type="primary"):
        with st.spinner("Generating audit report..."):
            report_path = os.path.join(os.path.dirname(__file__), "reports", "compliance_report.pdf")
            os.makedirs(os.path.dirname(report_path), exist_ok=True)
            generate_report(
                violations=filtered,
                risk_summary=risk_summary,
                posture_scores=posture,
                output_path=report_path,
            )
            st.session_state.report_path = report_path
        st.success(f"✅ Audit report generated with {len(filtered)} violations.")

with col_dl:
    if st.session_state.report_path and os.path.exists(st.session_state.report_path):
        with open(st.session_state.report_path, "rb") as f:
            st.download_button(
                label="⬇️ Download PDF Report",
                data=f.read(),
                file_name=f"SME_Compliance_Report_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf",
                mime="application/pdf",
                use_container_width=True,
            )

# ── Footer ────────────────────────────────────────────────────────────────────
st.divider()
st.markdown("""
<p style='text-align:center; color:#999; font-size:11px;'>
SME Compliance Monitor v1.0.0 &nbsp;|&nbsp; Opoku Mensah (w25035430) &nbsp;|&nbsp; Northumbria University &nbsp;|&nbsp;
Aligned to UK GDPR · ISO/IEC 27001:2022 · NIST CSF 2.0 · Cyber Essentials (NCSC)
</p>
""", unsafe_allow_html=True)
