# Validation Report: Detection 20 - Token Impersonation

## Simulated Scenario

**MITRE ATT&CK:** T1134.001 (Token Impersonation/Theft)
**Description:** Creation of a process with elevated privileges by stealing or impersonating another user's access token (e.g., SYSTEM).

## Lab Execution

Simulated using the Meterpreter module (`getsystem`) / Incognito or a custom tool. Generation of logons with special privileges.

## Results

* **SPL Triggered:** True Positive
* **KQL Triggered:** True Positive
* **Detected Events:** EventCode 4672 (Special privileges assigned to new logon).
