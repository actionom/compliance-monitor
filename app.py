"""
compliance_monitor/app.py
--------------------------
SME Compliance Monitor — Streamlit Dashboard v2.0.0
NEW in v2.0.0: Client Audit Mode — ingest real client log files (CSV/JSON)
Author : Opoku Mensah (w25035430)
Version: 2.0.0
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime
from modules.data_collector import collect_all_events
from modules.policy_engine import evaluate_all_events, compute_compliance_posture, get_risk_summary
from modules.alert_manager import process_alerts, get_escalated
from modules.report_generator import generate_report
from modules.control_matrix import get_categories, get_all_controls
from modules.client_ingestion import (ingest_client_file, get_template_csv,
    get_all_source_names, get_source_description, get_required_columns)

st.set_page_config(page_title="SME Compliance Monitor",page_icon="🛡️",layout="wide",initial_sidebar_state="expanded")
st.markdown("""<style>
.main{background-color:#f8f9fa}
.metric-card{background:white;border-radius:8px;padding:16px;border-left:5px solid;box-shadow:0 2px 4px rgba(0,0,0,0.08)}
.critical{border-left-color:#FF3B30}.high{border-left-color:#FF9500}
.medium{border-left-color:#FFCC00}.low{border-left-color:#34C759}
.escalated-banner{background:#FF3B30;color:white;padding:10px 16px;border-radius:6px;font-weight:bold;margin-bottom:12px}
.header-brand{background:linear-gradient(135deg,#1F497D 0%,#2E75B6 100%);color:white;padding:20px 24px;border-radius:10px;margin-bottom:20px}
.client-card{background:white;border-radius:8px;padding:16px;border-left:5px solid #2E75B6;box-shadow:0 2px 4px rgba(0,0,0,0.08);margin-bottom:12px}
.success-banner{background:#34C759;color:white;padding:10px 16px;border-radius:6px;font-weight:bold;margin-bottom:12px}
.info-box{background:#E8F4FD;border-left:4px solid #2E75B6;padding:12px 16px;border-radius:4px;margin:8px 0}
</style>""",unsafe_allow_html=True)

for key,default in [("violations",[]),("client_violations",[]),("last_refresh",None),
    ("report_path",None),("active_mode","simulation"),("ingestion_log",[]),("client_name","")]:
    if key not in st.session_state:st.session_state[key]=default

def load_sim(n=4):
    events=collect_all_events(events_per_control=n)
    st.session_state.violations=process_alerts(evaluate_all_events(events))
    st.session_state.last_refresh=datetime.now().strftime("%d %b %Y %H:%M:%S")

with st.sidebar:
    st.markdown("<div style='text-align:center;padding:10px 0'><h3 style='color:#1F497D;margin:0'>🛡️ SME Compliance Monitor</h3><p style='color:#666;font-size:11px;margin:4px 0'>v2.0.0 | Opoku Mensah</p></div>",unsafe_allow_html=True)
    st.divider()
    mode=st.radio("🎯 Mode",["🔬 Simulation Mode","🏢 Client Audit Mode"])
    st.session_state.active_mode="simulation" if "Simulation" in mode else "client"
    st.divider()
    if st.session_state.active_mode=="simulation":
        epc=st.slider("Events per Control Rule",1,8,4)
        if st.button("🔄 Refresh Data",use_container_width=True,type="primary"):
            with st.spinner("Loading..."):load_sim(epc)
            st.success("Refreshed.")
    else:
        cn=st.text_input("Client Name",placeholder="e.g. Acme Ltd")
        if cn:st.session_state.client_name=cn
    st.divider()
    severity_filter=st.multiselect("Severity",["Critical","High","Medium","Low"],default=["Critical","High","Medium","Low"])
    category_filter=st.multiselect("Category",get_categories(),default=get_categories())
    tier_filter=st.multiselect("Tier",["On-Premises","Cloud","Hybrid"],default=["On-Premises","Cloud","Hybrid"])
    st.divider()
    for fw in ["UK GDPR / DPA 2018","ISO 27001:2022","NIST CSF 2.0","Cyber Essentials"]:st.markdown(f"✅ {fw}")
    if st.session_state.last_refresh:st.caption(f"Last refresh: {st.session_state.last_refresh}")

if not st.session_state.violations:
    with st.spinner("Initialising..."):load_sim()

mode_badge="🔬 Simulation Mode" if st.session_state.active_mode=="simulation" else f"🏢 Client Audit: {st.session_state.client_name or 'No client loaded'}"
st.markdown(f"<div class='header-brand'><h2 style='margin:0;color:white'>🛡️ SME Compliance Monitor</h2><p style='margin:4px 0 0 0;color:#BDD7EE;font-size:14px'>{mode_badge} &nbsp;|&nbsp; UK GDPR &nbsp;·&nbsp; ISO 27001:2022 &nbsp;·&nbsp; NIST CSF 2.0 &nbsp;·&nbsp; Cyber Essentials</p></div>",unsafe_allow_html=True)

tab1,tab2,tab3=st.tabs(["📊 Live Dashboard","🏢 Client Audit — Upload Logs","📖 Control Matrix"])

def render_dashboard(source_viol,filtered):
    escalated=get_escalated(filtered)
    if escalated:st.markdown(f"<div class='escalated-banner'>🚨 ESCALATION ALERT — {len(escalated)} violation(s) breached SLA and require IMMEDIATE attention.</div>",unsafe_allow_html=True)
    risk=get_risk_summary(filtered)
    c1,c2,c3,c4,c5=st.columns(5)
    for col,lbl,val,css in[(c1,"🔴 Critical",risk["Critical"],"critical"),(c2,"🟠 High",risk["High"],"high"),(c3,"🟡 Medium",risk["Medium"],"medium"),(c4,"🟢 Low",risk["Low"],"low"),(c5,"📊 Total",risk["Total"],"critical" if risk["Critical"]>0 else "low")]:
        with col:st.markdown(f"<div class='metric-card {css}'><div style='font-size:13px;color:#666'>{lbl}</div><div style='font-size:36px;font-weight:bold;color:#1F497D'>{val}</div></div>",unsafe_allow_html=True)
    st.markdown("<br>",unsafe_allow_html=True)
    cl,cr=st.columns(2)
    with cl:
        st.subheader("📊 Violations by Category")
        if filtered:
            df2=pd.Series([v["category"] for v in filtered]).value_counts().reset_index();df2.columns=["Category","Count"]
            fig=px.bar(df2,x="Count",y="Category",orientation="h",color="Count",color_continuous_scale=["#34C759","#FFCC00","#FF9500","#FF3B30"],template="plotly_white")
            fig.update_layout(height=300,margin=dict(l=0,r=0,t=10,b=0),coloraxis_showscale=False);st.plotly_chart(fig,use_container_width=True)
    with cr:
        st.subheader("🍩 Severity Distribution")
        if filtered:
            sc=pd.Series([v["severity"] for v in filtered]).value_counts();sc_col={"Critical":"#FF3B30","High":"#FF9500","Medium":"#FFCC00","Low":"#34C759"}
            fig2=go.Figure(go.Pie(labels=sc.index.tolist(),values=sc.values.tolist(),hole=0.5,marker_colors=[sc_col.get(s,"#ccc") for s in sc.index]))
            fig2.update_layout(height=300,margin=dict(l=0,r=0,t=10,b=0),legend=dict(orientation="h",yanchor="bottom",y=-0.2));st.plotly_chart(fig2,use_container_width=True)
    st.subheader("🎯 Framework Compliance Posture")
    posture=compute_compliance_posture(filtered)
    fw={"GDPR":"UK GDPR / DPA 2018","ISO27001":"ISO/IEC 27001:2022","NIST_CSF":"NIST CSF 2.0","Cyber_Essentials":"Cyber Essentials (NCSC)"}
    cols=st.columns(4)
    for col,(fk,fn) in zip(cols,fw.items()):
        sc2=posture.get(fk,0);col2="#34C759" if sc2>=70 else "#FF9500" if sc2>=40 else "#FF3B30"
        with col:st.markdown(f"<div style='background:white;border-radius:8px;padding:14px;box-shadow:0 2px 4px rgba(0,0,0,0.08);text-align:center'><div style='font-size:11px;color:#666;font-weight:600'>{fn}</div><div style='font-size:40px;font-weight:bold;color:{col2}'>{sc2}%</div><div style='background:#eee;border-radius:4px;height:8px;margin-top:6px'><div style='background:{col2};width:{sc2}%;height:100%;border-radius:4px'></div></div></div>",unsafe_allow_html=True)
    st.markdown("<br>",unsafe_allow_html=True)
    ct,cc=st.columns(2)
    with ct:
        st.subheader("🏗️ By Deployment Tier")
        if filtered:
            td=pd.Series([v["source_tier"] for v in filtered]).value_counts().reset_index();td.columns=["Tier","Count"]
            fig3=px.pie(td,values="Count",names="Tier",color="Tier",color_discrete_map={"On-Premises":"#1F497D","Cloud":"#2E75B6","Hybrid":"#9DC3E6"},template="plotly_white")
            fig3.update_layout(height=260,margin=dict(l=0,r=0,t=10,b=0));st.plotly_chart(fig3,use_container_width=True)
    with cc:
        st.subheader("📈 By Control ID")
        if filtered:
            cd=pd.Series([v["control_id"] for v in filtered]).value_counts().head(10).reset_index();cd.columns=["Control","Count"]
            fig4=px.bar(cd,x="Control",y="Count",color="Count",color_continuous_scale=["#BDD7EE","#FF3B30"],template="plotly_white")
            fig4.update_layout(height=260,margin=dict(l=0,r=0,t=10,b=0),coloraxis_showscale=False);st.plotly_chart(fig4,use_container_width=True)
    st.subheader("📋 Live Violation Feed")
    if filtered:
        dfd=pd.DataFrame([{"Severity":v["severity"],"Control ID":v["control_id"],"Violation":v["control_name"],"Category":v["category"],"Host":v["hostname"],"User":v["user"],"Source":v["source_system"],"Tier":v["source_tier"],"GDPR Ref":v["gdpr_clause"][:40],"ISO 27001":v["iso27001_clause"][:35],"Timestamp":v["timestamp"],"SLA Deadline":v["sla_deadline"],"Escalated":"🚨 YES" if v.get("escalation_required") else "✅ No","Owner":v.get("remediation_owner",""),"Detail":v.get("detail","")} for v in filtered])
        def csev(val):
            c={"Critical":"background-color:#FFE5E5;color:#C00000;font-weight:bold;","High":"background-color:#FFF3E0;color:#C56011;font-weight:bold;","Medium":"background-color:#FFFDE7;color:#9B7600;","Low":"background-color:#E8F5E9;color:#376023;"};return c.get(val,"")
        st.dataframe(dfd.style.applymap(csev,subset=["Severity"]),use_container_width=True,height=400)
        cl2=st.session_state.client_name.replace(" ","_") if st.session_state.client_name else ""
        st.download_button("⬇️ Download Violations (CSV)",dfd.to_csv(index=False),f"violations{'_'+cl2 if cl2 else ''}_{datetime.now().strftime('%Y%m%d_%H%M')}.csv","text/csv")
    else:st.success("✅ No violations match current filters.")
    st.subheader("📄 Audit Report Generation")
    r1,r2=st.columns([2,1])
    with r1:
        if st.button("🖨️ Generate PDF Compliance Audit Report",use_container_width=True,type="primary"):
            with st.spinner("Generating..."):
                rp=os.path.join(os.path.dirname(__file__),"reports","compliance_report.pdf")
                os.makedirs(os.path.dirname(rp),exist_ok=True)
                generate_report(filtered,risk,posture,rp,client_name=st.session_state.client_name)                 st.session_state.report_path=rp
            st.success(f"✅ Report generated — {len(filtered)} violations.")
    with r2:
        if st.session_state.report_path and os.path.exists(st.session_state.report_path):
            with open(st.session_state.report_path,"rb") as f:
                cl2=st.session_state.client_name.replace(" ","_") if st.session_state.client_name else ""
                st.download_button("⬇️ Download PDF Report",f.read(),f"SME_Compliance_Report{'_'+cl2 if cl2 else ''}_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf","application/pdf",use_container_width=True)

with tab1:
    sv=st.session_state.client_violations if (st.session_state.active_mode=="client" and st.session_state.client_violations) else st.session_state.violations
    filtered=[v for v in sv if v.get("severity") in severity_filter and v.get("category") in category_filter and v.get("source_tier") in tier_filter]
    render_dashboard(sv,filtered)

with tab2:
    st.markdown("<div class='header-brand' style='padding:16px 20px'><h3 style='margin:0;color:white'>🏢 Client Audit — Log Ingestion Engine</h3><p style='margin:4px 0 0 0;color:#BDD7EE;font-size:13px'>Upload real client log exports — Windows Event Logs, Azure AD, Firewall, EDR, Generic CSV</p></div>",unsafe_allow_html=True)
    with st.expander("📖 How To Use Client Audit Mode",expanded=False):
        st.markdown("""
**STEP 1** — Enter the **Client Name** in the sidebar

**STEP 2** — Download a **Sample Template** below and send to client IT team

**STEP 3** — Ask IT team to export logs in that format:
- Windows: `eventvwr.msc` → Action → Save All Events As → CSV
- Azure AD: Portal → Azure AD → Sign-in logs → Download → CSV  
- Firewall: Management console → Logs → Export → CSV
- EDR (CrowdStrike/Defender/Sophos): Detections → Export CSV

**STEP 4** — Select the **Log Source Type** and upload the file

**STEP 5** — Switch to **📊 Live Dashboard** tab to view full analysis

**STEP 6** — Click **Generate PDF Audit Report** and download for client delivery
        """)
    st.divider()
    if not st.session_state.client_name:
        st.warning("⚠️ Please enter a **Client Name** in the sidebar first.")
    st.subheader("📥 Step 1 — Download Sample Log Templates")
    st.markdown("Send these to the client's IT team so they export logs in the correct format.")
    snames=get_all_source_names();tcols=st.columns(3)
    for i,src in enumerate(snames):
        with tcols[i%3]:
            st.markdown(f"<div class='client-card'><strong style='color:#1F497D'>{src}</strong><br><span style='font-size:12px;color:#666'>{get_source_description(src)}</span><br><span style='font-size:11px;color:#888'>Required: {', '.join(get_required_columns(src)[:3])}</span></div>",unsafe_allow_html=True)
            st.download_button("⬇️ Download Template",get_template_csv(src),f"template_{src.replace(' ','_').replace('/','_')}.csv","text/csv",key=f"t{i}",use_container_width=True)
    st.divider()
    st.subheader("📤 Step 2 — Upload Client Log File")
    uc1,uc2=st.columns(2)
    with uc1:
        sel_src=st.selectbox("Log Source Type",snames)
        st.markdown(f"<div class='info-box'><strong>Format:</strong> {get_source_description(sel_src)}<br><strong>Required columns:</strong> {', '.join(get_required_columns(sel_src))}</div>",unsafe_allow_html=True)
    with uc2:
        upf=st.file_uploader("Choose log file (CSV or JSON)",type=["csv","json"],key="single_up")
    if upf is not None:
        cn2=st.session_state.client_name or "Unknown Client"
        with st.spinner(f"Ingesting {upf.name}..."):
            res=ingest_client_file(upf.read(),upf.name,sel_src,cn2)
        if res["errors"]:
            for e in res["errors"]:st.error(f"❌ {e}")
        elif res["violations_found"]==0:
            st.warning(f"⚠️ Parsed {res['rows_parsed']} rows but no violations mapped. Check log source type matches your file.")
        else:
            st.markdown(f"<div class='success-banner'>✅ {res['violations_found']} violations mapped from {res['rows_parsed']} rows for: {cn2}</div>",unsafe_allow_html=True)
            proc=process_alerts(evaluate_all_events(res["events"]))
            st.session_state.client_violations=proc;st.session_state.active_mode="client"
            st.session_state.ingestion_log.append({"Timestamp":res["ingestion_time"],"Client":cn2,"File":upf.name,"Source":sel_src,"Rows":res["rows_parsed"],"Violations":res["violations_found"]})
            rk=get_risk_summary(proc);m1,m2,m3,m4,m5=st.columns(5)
            for col,lbl,val,col3 in[(m1,"🔴 Critical",rk["Critical"],"#FF3B30"),(m2,"🟠 High",rk["High"],"#FF9500"),(m3,"🟡 Medium",rk["Medium"],"#FFCC00"),(m4,"🟢 Low",rk["Low"],"#34C759"),(m5,"📊 Total",rk["Total"],"#1F497D")]:
                with col:st.markdown(f"<div style='background:white;border-radius:8px;padding:12px;border-left:4px solid {col3};text-align:center;box-shadow:0 2px 4px rgba(0,0,0,0.08)'><div style='font-size:12px;color:#666'>{lbl}</div><div style='font-size:30px;font-weight:bold;color:{col3}'>{val}</div></div>",unsafe_allow_html=True)
            st.markdown("<br>",unsafe_allow_html=True)
            st.info("✅ Switch to **📊 Live Dashboard** tab to view full analysis and generate the PDF report.")
            st.subheader("🔍 Violation Preview — Top 10")
            pv=pd.DataFrame([{"Severity":v["severity"],"Control":v["control_name"],"Category":v["category"],"Host":v["hostname"],"User":v["user"],"Detail":v.get("detail","")[:80],"GDPR":v["gdpr_clause"][:35]} for v in proc[:10]])
            def cs2(val):
                c={"Critical":"background-color:#FFE5E5;color:#C00000;font-weight:bold;","High":"background-color:#FFF3E0;color:#C56011;font-weight:bold;","Medium":"background-color:#FFFDE7;color:#9B7600;","Low":"background-color:#E8F5E9;color:#376023;"};return c.get(val,"")
            st.dataframe(pv.style.applymap(cs2,subset=["Severity"]),use_container_width=True)
    st.divider()
    st.subheader("📦 Step 3 — Upload Multiple Files (Full Audit)")
    mf=st.file_uploader("Upload multiple log files",type=["csv","json"],accept_multiple_files=True,key="multi_up")
    if mf:
        ms=st.selectbox("Log Source Type (applies to all)",snames,key="ms2")
        if st.button("🚀 Process All Files",type="primary",use_container_width=True):
            all_ev=[];cn3=st.session_state.client_name or "Unknown Client";prog=st.progress(0)
            for i,f in enumerate(mf):
                r2=ingest_client_file(f.read(),f.name,ms,cn3);all_ev.extend(r2["events"])
                st.write(f"✅ {f.name} — {r2['violations_found']} violations");prog.progress((i+1)/len(mf))
            if all_ev:
                proc2=process_alerts(evaluate_all_events(all_ev));st.session_state.client_violations=proc2;st.session_state.active_mode="client"
                rk2=get_risk_summary(proc2);st.success(f"✅ Done — {len(proc2)} total violations | C:{rk2['Critical']} H:{rk2['High']} M:{rk2['Medium']}")
                st.info("Switch to **📊 Live Dashboard** tab.")
    st.divider()
    if st.session_state.ingestion_log:
        st.subheader("📋 Ingestion History")
        st.dataframe(pd.DataFrame(st.session_state.ingestion_log),use_container_width=True)
        if st.button("🗑️ Clear History"):
            st.session_state.ingestion_log=[];st.session_state.client_violations=[];st.rerun()

with tab3:
    st.subheader("📖 Compliance Control Matrix — Full Reference")
    ctrl_df=pd.DataFrame([{"ID":c["control_id"],"Control Name":c["name"],"Category":c["category"],"Severity":c["default_severity"],"UK GDPR":c["gdpr_clause"],"ISO 27001":c["iso27001_clause"],"NIST CSF":c["nist_csf"],"Cyber Essentials":c["cyber_essentials"]} for c in get_all_controls()])
    st.dataframe(ctrl_df,use_container_width=True,height=500)

st.divider()
st.markdown("<p style='text-align:center;color:#999;font-size:11px'>SME Compliance Monitor v2.0.0 &nbsp;|&nbsp; Opoku Mensah &nbsp;|&nbsp; Cybersecurity Consultant &nbsp;|&nbsp; UK GDPR · ISO/IEC 27001:2022 · NIST CSF 2.0 · Cyber Essentials</p>",unsafe_allow_html=True)
