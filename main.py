import random
import time
from typing import List, Dict, Any, Annotated
import hashlib
from dotenv import load_dotenv
import os
import operator
import requests

load_dotenv()

class Enterprisenetwork:
    def __init__(self):
        self.threat_intel_db = {
            "192.168.1.50": {"status": "malicious", "actor": "Lazarus Group", "type": "Ransomware Node"},
            "10.0.0.99": {"status": "suspicious", "actor": "Unknown", "type": "Aggressive Port Scanner"},
            "172.16.254.1": {"status": "malicious", "actor": "APT29", "type": "Command & Control (C2)"}
        }

        # firewall
        self.blocked_ips = set()
        
        # audit ledger
        self.rubix_ledger = []

    def generate_server_logs(self, attack_mode=True) -> List[Dict]:
        # simulate 5 sec network traffic
        logs = [
            {"timestamp": time.time(), "ip": "192.168.1.15", "event": "Successful SSH Login", "status": "OK"},
            {"timestamp": time.time(), "ip": "10.1.2.3", "event": "API Request /v1/users", "status": "OK"},
        ]

        # if attack mode true -> coordinated brute force attack
        if attack_mode:
            logs.extend([
                # A known, highly malicious Tor Exit Node / Scanner
                {"timestamp": time.time(), "ip": "185.220.101.14", "event": "Failed SSH Login - root", "status": "FAIL"},
                {"timestamp": time.time(), "ip": "185.220.101.14", "event": "Failed SSH Login - admin", "status": "FAIL"},
                {"timestamp": time.time(), "ip": "185.220.101.14", "event": "Mass Data Egress Started", "status": "CRITICAL"}
            ])

            random.shuffle(logs)
        return logs


network = Enterprisenetwork()

from typing import TypedDict

class SOCstate(TypedDict):
    raw_logs: List[Dict]
    suspicious_ips: List[str]
    threat_reports: Annotated[List[Dict], operator.add]
    severity: str
    action_plan: str
    audit_receipt: str

    incident_report: str
        
# threat hunter tool
def check_ip_reputation(ip_address: str) -> Dict:
    """Queries the AbuseIPDB API for live global threat intelligence."""
    
    
    if ip_address.startswith(("192.168.", "10.", "172.16.")):
         return {"status": "internal", "actor": "Local Network", "type": "Private IP"}

    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        return {"status": "error", "actor": "System", "type": "Missing AbuseIPDB API Key"}

    print(f"    [API CALL] Fetching global intel for {ip_address}...")
    
    url = "https://api.abuseipdb.com/api/v2/check"
    querystring = {
        'ipAddress': ip_address,
        'maxAgeInDays': '90' # Check for reports in the last 3 months
    }
    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }

    try:
        response = requests.get(url, headers=headers, params=querystring, timeout=5)
        response.raise_for_status()
        data = response.json()["data"]

        # live response
        confidence_score = data.get("abuseConfidenceScore", 0)
        usage_type = data.get("usageType", "Unknown")
        domain = data.get("domain", "Unknown")
        total_reports = data.get("totalReports", 0)

        # Translate the score 
        if confidence_score > 75:
            status = "malicious"
        elif confidence_score > 25:
            status = "suspicious"
        else:
            status = "clean"

        return {
            "status": status,
            "actor": domain,
            "type": f"Abuse Score: {confidence_score}/100 | Total Reports: {total_reports} | Type: {usage_type}"
        }

    except Exception as e:
        print(f"    [API ERROR] {e}")
        return {"status": "unknown", "actor": "None", "type": "API Fetch Failed"}    
        
# incident responder tool
def block_ip_on_firewall(ip_address: str) -> str:
    """block an IP at network edge."""
    network.blocked_ips.add(ip_address)
    return f"SUCCESS: {ip_address} blocked on edge firewall."
        
def log_rubix_audit_trail(action: str, llm_reasoning: str) -> str:
    """hashes AI's reasoning and commits it to the mock blockchain."""
    timestamp = str(time.time())
    payload = f"{timestamp}|{action}|{llm_reasoning}"

    # hash payload
    block_hash = hashlib.sha256(payload.encode()).hexdigest()

    receipt = {
        "timestamp": timestamp,
        "action": action,
        "hash": block_hash,
        "verified": True
    }
    network.rubix_ledger.append(receipt)
    return f"Rubix Audit HASH: {block_hash}"
        
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field

# op format
class Monitoroutput(BaseModel):
    # FIXED: Was suspicious_pis
    suspicious_ips: List[str] = Field(description="List of IP addresses showing malicious or highly suspicious activity.")

# llm
llm_fast = ChatOpenAI(
    api_key=os.getenv("GROQ_API_KEY"),
    base_url="https://api.groq.com/openai/v1",
    model="llama-3.3-70b-versatile",
    temperature=0
)
monitor_agent = llm_fast.with_structured_output(Monitoroutput, method="json_mode")

# node
def network_monitor_node(state: SOCstate):
    print("[MONITOR] scanning network logs")
    prompt = f"""
    You are an enterprise Network Monitor. Review the following firewall and server logs.
    Identify any IP addresses exhibiting suspicious behavior (Failed logins, Port Scans, Data Egress).
    Ignore normal traffic.
    
    You must respond in JSON format with exactly one key:
    "suspicious_ips": A list of strings containing only the raw IP addresses.
    
    Example: {{"suspicious_ips": ["192.168.1.50", "10.0.0.99"]}}
    
    Logs:
    {state['raw_logs']}
    """

    result = monitor_agent.invoke(prompt)
    print(f"Flagged IPs: {result.suspicious_ips}") 
    return {"suspicious_ips": result.suspicious_ips}

# parallel nodes
class Hunterstate(TypedDict):
    ip: str

def threat_hunter_node(state: Hunterstate):
    ip = state["ip"]
    print(f"[HUNTER] Investigating IP: {ip}")

    # tool
    intel = check_ip_reputation(ip)

    report = {
        "ip": ip,
        "intel": intel,
        "summary": f"IP {ip} is flagged as {intel['status']}. Known actor: {intel['actor']}. Type: {intel['type']}."
    }

    print(f"Intel gathered for {ip}: {intel['status'].upper()}")
    return {"threat_reports": [report]}

# op format
class Analystdecision(BaseModel):
    severity: str = Field(description="Must be LOW, MEDIUM, HIGH, or CRITICAL")
    action_plan: str = Field(description="Detailed commands for the Incident Responder. E.g., 'QUARANTINE 192.168.1.50'")
    reasoning: str = Field(description="Strict explanation of why this action was chosen. This will be hashed on the blockchain.")

llm_smart = ChatOpenAI(
    api_key=os.getenv("GROQ_API_KEY"),
    base_url="https://api.groq.com/openai/v1",
    model="llama-3.3-70b-versatile",
    temperature=0
)
analyst_agent = llm_smart.with_structured_output(Analystdecision, method="json_mode")

# node
def security_analyst_node(state: SOCstate):
    print("[ANALYST] Evaluating Threats")

    prompt = f"""
    You are the Lead SOC Analyst. You have zero tools. Your job is pure reasoning.
    Review the original suspicious IPs and the threat intelligence reports gathered by your swarm.
    
    Suspicious IPs: {state['suspicious_ips']}
    Threat Intel Reports: {state['threat_reports']}
    
    Determine the severity of the overall situation.
    If an IP belongs to an APT or is executing ransomware/mass egress, classify as CRITICAL and order a quarantine.
    If it is a harmless scan, classify as LOW.
    
    You must respond in JSON format with exactly three keys:
    "severity": Must be exactly LOW, MEDIUM, HIGH, or CRITICAL.
    "action_plan": Detailed commands for the Incident Responder. E.g., 'QUARANTINE 192.168.1.50'
    "reasoning": Strict explanation of why this action was chosen.
    """

    decision = analyst_agent.invoke(prompt)

    print(f" Severity: {decision.severity}")
    print(f" Action Plan: {decision.action_plan}")

    return {
        "severity": decision.severity,
        "action_plan": f"COMMAND: {decision.action_plan} | REASONING: {decision.reasoning}" 
    }

from langchain_core.messages import HumanMessage
from langchain.agents import create_agent

# python fn as tools
responder_tools = [block_ip_on_firewall, log_rubix_audit_trail]
# react agent - execute tools
responder_agent = create_agent(llm_smart, tools=responder_tools)

# node
def incident_responder_node(state: SOCstate):
    print("[RESPONDER] Executing Actions & Committing Audit Trail")
    
    if "CRITICAL" not in state["severity"] and "HIGH" not in state["severity"]:
        print("  No critical actions required. Standing by.")
        return {"audit_receipt": "No action taken."}
    
    prompt = f"""
    You are the Incident Responder. Execute the following action plan provided by the Analyst.
    
    ACTION PLAN AND REASONING:
    {state['action_plan']}
    
    Tasks:
    1. Extract any IPs that need to be quarantined and use the 'block_ip_on_firewall' tool.
    2. Extract the REASONING and use the 'log_rubix_audit_trail' tool to commit the action to the blockchain.
    """

    
    result = responder_agent.invoke({"messages": [HumanMessage(content=prompt)]})

    # final op message
    final_response = result["messages"][-1].content
    print(f"{final_response}")
    return {"audit_receipt": final_response}


def post_mortem_reporter_node(state: SOCstate):
    print("[REPORTER] Drafting Post-Mortem Incident Report...")
    
    prompt = f"""
    You are a Senior Cyber Threat Intelligence Analyst writing a post-mortem incident report for the C-Suite.
    Based on the following LangGraph state data, generate a clean, professional, and highly detailed Markdown report.

    INCIDENT DATA:
    - Raw Logs: {state.get('raw_logs')}
    - Threat Intelligence: {state.get('threat_reports')}
    - Declared Severity: {state.get('severity')}
    - AI Action Plan & Reasoning: {state.get('action_plan')}
    - Blockchain Audit Receipt: {state.get('audit_receipt')}

    The report MUST contain the following sections:
    1. **Executive Summary**: A brief, high-level overview of what happened and the outcome.
    2. **Incident Timeline**: A bulleted list of the events.
    3. **Threat Intelligence Details**: Details on the malicious IPs, actors, and AbuseIPDB scores.
    4. **Remediation Actions**: What the Incident Responder executed.
    5. **Cryptographic Audit Trail**: The Rubix blockchain hash to prove policy compliance.

    Do not include any pleasantries. Output strictly the Markdown text.
    """

    
    response = llm_smart.invoke(prompt)
    report_content = response.content

    # report 
    with open("report.md", "w", encoding="utf-8") as f:
        f.write(report_content)

    print("[REPORTER] Report successfully saved to 'report.md'")
    
    return {"incident_report": report_content}


from langgraph.graph import StateGraph, START, END
from langgraph.types import Send 
from langgraph.checkpoint.memory import MemorySaver

workflow = StateGraph(SOCstate)

workflow.add_edge(START, "network_monitor")

workflow.add_node("network_monitor", network_monitor_node)
workflow.add_node("threat_hunter", threat_hunter_node)
workflow.add_node("security_analyst", security_analyst_node)
workflow.add_node("incident_responder", incident_responder_node)

workflow.add_node("post_mortem_reporter", post_mortem_reporter_node)

def map_suspicious_ips(state: SOCstate):
    """Dynamically spawns parallel Threat Hunters based on Monitor output."""
    suspicious_ips = state.get("suspicious_ips", [])
    
    
    if not suspicious_ips:
        print("--- [ROUTER] No threats detected. Standing down. ---")
        return END 
        
    
    DEMO_LIMIT = 3
    ips_to_process = suspicious_ips[:DEMO_LIMIT]
    
    print(f"--- [ROUTER] Fanning out to {len(ips_to_process)} concurrent Threat Hunters ---")
    
    
    return [Send("threat_hunter", {"ip": ip}) for ip in ips_to_process]

workflow.add_conditional_edges(
    "network_monitor", 
    map_suspicious_ips, 
    ["threat_hunter", END] 
)

# Fan-In
workflow.add_edge("threat_hunter", "security_analyst")

workflow.add_edge("security_analyst", "incident_responder")

workflow.add_edge("incident_responder", "post_mortem_reporter")
workflow.add_edge("post_mortem_reporter", END)

memory = MemorySaver()

soc_swarm = workflow.compile(
    checkpointer=memory,
    interrupt_before=["incident_responder"] 
)

memory = MemorySaver()
soc_swarm = workflow.compile(
    checkpointer=memory,
    interrupt_before=["incident_responder"] 
)

if __name__ == "__main__":
    print("\n" + "="*50)
    print("INITIALIZING SOC SWARM")
    print("="*50 + "\n")

    initial_logs = network.generate_server_logs(attack_mode=True)
    initial_state = {"raw_logs": initial_logs}

    #  configuration with thread_id
    config = {"configurable": {"thread_id": "soc_incident_001"}}

    #  Start the graph
    print("\n>>> INGESTING LOGS INTO PIPELINE <<<\n")
    for event in soc_swarm.stream(initial_state, config, stream_mode="values"):
        pass

    snapshot = soc_swarm.get_state(config)
    next_step = snapshot.next

    if next_step and next_step[0] == "incident_responder":
        print("\n" + "!"*50)
        print("SYSTEM PAUSED FOR HUMAN REVIEW")
        print("!"*50)
        
        analyst_plan = snapshot.values.get("action_plan", "No plan found.")
        print(f"\nPROPOSED ACTION:\n{analyst_plan}\n")
        
        # human authorization
        user_input = input("Authorize Incident Responder to execute? (Y/N): ")
        
        if user_input.strip().upper() == 'Y':
            print("\n[AUTHORIZATION GRANTED] Resuming graph execution...\n")
            
            for event in soc_swarm.stream(None, config, stream_mode="values"):
                pass
                
            print("\n>>> INCIDENT RESOLVED <<<")
            
            print("\n--- FINAL RUBIX LEDGER STATE ---")
            for entry in network.rubix_ledger:
                print(entry)
                
        else:
            print("\n[AUTHORIZATION DENIED] Aborting execution.")
    else:
        print("\nPipeline finished without needing human intervention.")
