# **Incident Report**
## **Executive Summary**
A critical security incident occurred involving a malicious IP address, `185.220.101.14`, which was flagged with an abuse score of 100/100 and 169 total reports. The IP was associated with failed SSH login attempts, a mass data egress event, and was linked to the actor `artikel10.org`. The incident was mitigated by quarantining the IP address, and the action was recorded on the blockchain.

## **Incident Timeline**
* `1779777535.8146052`: Failed SSH Login - admin from `185.220.101.14` (FAIL)
* `1779777535.8146052`: API Request /v1/users from `10.1.2.3` (OK)
* `1779777535.8146052`: Mass Data Egress Started from `185.220.101.14` (CRITICAL)
* `1779777535.8146052`: Successful SSH Login from `192.168.1.15` (OK)
* `1779777535.8146052`: Failed SSH Login - root from `185.220.101.14` (FAIL)

## **Threat Intelligence Details**
The malicious IP address, `185.220.101.14`, has been flagged with the following threat intelligence:
* **Abuse Score**: 100/100
* **Total Reports**: 169
* **Actor**: `artikel10.org`
* **Type**: Commercial
This IP address poses a significant threat due to its high abuse score and the number of reports associated with it.

## **Remediation Actions**
The Incident Responder executed the following remediation action:
* **Quarantine**: The IP address `185.220.101.14` was quarantined to prevent further malicious activity.

## **Cryptographic Audit Trail**
The remediation action was recorded on the blockchain with the following hash:
* **Blockchain Hash**: `b93cd4745ce19e438f78aa49119a880b4130ab06dd5ebf49e3ab6411e7fd4667`
This hash serves as proof of policy compliance and provides a tamper-evident record of the incident response actions taken.