# Autonomous AI Security Operations Center (SOC) Swarm

An autonomous multi-agent Security Operations Center built using LangGraph, Streamlit, and Groq powered Llama 3 models.  
The system automates threat detection, enrichment, response execution, and incident reporting while maintaining a cryptographic audit trail for every AI-driven security decision.

---

# Project Overview

This project simulates an enterprise SOC environment where multiple AI agents collaborate to monitor network activity, investigate suspicious IPs, assess threat severity, execute remediation actions, and generate compliance-ready incident reports.

The system is designed to solve two major cybersecurity challenges:

- **Alert Fatigue** — Automating repetitive SOC workflows such as log triaging and threat enrichment.
- **AI Trust & Auditability** — Providing cryptographic proof for every autonomous AI decision through blockchain-style hashing.

The architecture is implemented as a LangGraph multi-agent workflow with Human-In-The-Loop (HITL) approval before executing critical security actions.

---

# Multi-Agent Workflow

## 1. Network Monitor Agent
- Scans incoming server and firewall logs.
- Detects suspicious behaviors such as:
  - Failed SSH logins
  - Port scanning
  - Mass data egress
- Filters normal traffic and extracts suspicious IP addresses.

---

## 2. Threat Hunter Agent
- Runs concurrently for every suspicious IP.
- Queries the AbuseIPDB API for live threat intelligence.
- Collects:
  - Abuse confidence scores
  - Total reports
  - Actor/domain information
  - Usage type

---

## 3. Security Analyst Agent
- Uses Llama 3.3 70B through Groq for reasoning.
- Evaluates:
  - Raw network logs
  - Threat intelligence reports
- Determines:
  - Threat severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`)
  - Recommended remediation action
  - Detailed reasoning for the decision

---

## 4. Incident Responder Agent
- Waits for Human-In-The-Loop authorization before execution.
- Executes firewall blocking actions on malicious IPs.
- Generates a cryptographic SHA-256 audit hash of the AI reasoning.
- Stores the audit receipt inside a mock blockchain ledger.

---

## 5. Reporter Agent
- Automatically generates a professional Markdown incident report.
- Includes:
  - Executive summary
  - Threat intelligence findings
  - Incident timeline
  - Remediation steps
  - Cryptographic audit trail

---

# System Workflow

```text
Raw Logs
   ↓
Network Monitor
   ↓
Suspicious IP Detection
   ↓
Parallel Threat Hunters
   ↓
Threat Intelligence Enrichment
   ↓
Security Analyst Reasoning
   ↓
Human Approval (HITL)
   ↓
Incident Responder
   ↓
Firewall Block + Blockchain Audit
   ↓
Report Generation