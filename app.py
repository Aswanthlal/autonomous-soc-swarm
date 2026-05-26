import streamlit as st
import time
import pandas as pd
from main import soc_swarm, network 

# --- UI Configuration ---
st.set_page_config(page_title="SOC Swarm Command Center", page_icon="🛡️", layout="wide")

st.title("🛡️ Autonomous SOC Command Center")
st.markdown("Monitor live traffic, review AI threat intel, and authorize blockchain-audited remediation.")

# --- Session State Management ---
if "thread_id" not in st.session_state:
    st.session_state.thread_id = "ui_session_001"
    st.session_state.config = {"configurable": {"thread_id": st.session_state.thread_id}}
    st.session_state.pipeline_started = False
    st.session_state.awaiting_authorization = False
    st.session_state.incident_resolved = False

# Sidebar
with st.sidebar:
    st.header("Control Panel")
    if st.button("INGEST LIVE LOGS", type="primary", use_container_width=True):
        st.session_state.pipeline_started = True
        st.session_state.awaiting_authorization = False
        st.session_state.incident_resolved = False
        
        network.rubix_ledger = [] 
        
        initial_logs = network.generate_server_logs(attack_mode=True)
        initial_state = {"raw_logs": initial_logs}
        
        for event in soc_swarm.stream(initial_state, st.session_state.config, stream_mode="values"):
            pass 
        
        snapshot = soc_swarm.get_state(st.session_state.config)
        if snapshot.next and snapshot.next[0] == "incident_responder":
            st.session_state.awaiting_authorization = True
            
    st.divider()
    st.markdown("**Swarm Status**")
    if not st.session_state.pipeline_started:
        st.info("Idle. Waiting for log ingestion.")
    elif st.session_state.awaiting_authorization:
        st.warning("⚠️ Paused: Awaiting Human Authorization")
    elif st.session_state.incident_resolved:
        st.success("✅ Incident Resolved & Logged")

# layout: Main Content
if st.session_state.pipeline_started:
    snapshot = soc_swarm.get_state(st.session_state.config)
    current_state = snapshot.values

    st.subheader("📡 Raw Ingestion Logs (Monitor Agent)")
    logs_df = pd.DataFrame(current_state.get("raw_logs", []))

    def highlight_status(val):
        color = 'red' if val in ['FAIL', 'CRITICAL'] else 'orange' if val == 'WARN' else 'green'
        return f'color: {color}'
    if not logs_df.empty:
        st.dataframe(logs_df.style.map(highlight_status, subset=['status']), use_container_width=True)

    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Threat Intel (Hunter Agent)")
        reports = current_state.get("threat_reports", [])
        if reports:
            for report in reports:
                status = report['intel']['status'].upper()
                emoji = "🛑" if status == "MALICIOUS" else "⚠️" if status == "SUSPICIOUS" else "✅"
                with st.expander(f"{emoji} IP: {report['ip']} - {status}", expanded=True):
                    st.write(f"**Actor:** {report['intel']['actor']}")
                    st.write(f"**Details:** {report['intel']['type']}")
                    st.caption(report['summary'])
        else:
            st.write("No threats identified.")

    with col2:
        st.subheader("Security Analyst Decision")
        severity = current_state.get("severity", "UNKNOWN")
        
        if severity == "CRITICAL":
            st.error(f"**Severity Level:** {severity}")
        elif severity == "HIGH":
            st.warning(f"**Severity Level:** {severity}")
        else:
            st.info(f"**Severity Level:** {severity}")
            
        action_plan = current_state.get("action_plan", "No action plan generated.")
        st.code(action_plan, language="markdown")

    st.divider()

    if st.session_state.awaiting_authorization:
        st.subheader(" Human-In-The-Loop Authorization Required")
        st.markdown("The AI requires cryptographic authorization to execute infrastructure changes.")
        
        if st.button("AUTHORIZE FIREWALL BLOCK & HASH TO BLOCKCHAIN", type="primary"):
            with st.spinner("Executing commands and hashing to Rubix Network..."):

                for event in soc_swarm.stream(None, st.session_state.config, stream_mode="values"):
                    pass
                
                time.sleep(1) 
                st.session_state.awaiting_authorization = False
                st.session_state.incident_resolved = True
                st.rerun() 


    if st.session_state.incident_resolved:
        st.subheader("Incident Responder & Rubix Audit Ledger")
        st.success(current_state.get("audit_receipt", "Action executed."))
        
        st.markdown("### Immutable Blockchain Ledger")
        if network.rubix_ledger:
            ledger_df = pd.DataFrame(network.rubix_ledger)
            st.dataframe(ledger_df, use_container_width=True)
        else:
            st.write("No ledger entries for this session.")

        st.divider()
        st.subheader("C-Suite Post-Mortem Report")
        
        final_report = current_state.get("incident_report", "")
        
        if final_report:
            with st.expander("View Full Executive Report", expanded=False):
                st.markdown(final_report)
            
            st.download_button(
                label="Download report.md",
                data=final_report,
                file_name="incident_report.md",
                mime="text/markdown"
            )