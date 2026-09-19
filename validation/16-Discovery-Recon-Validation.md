# Validation Report: Detection 16 - Discovery Recon

## Simulated Scenario

**MITRE ATT&CK:** TA0007 (Discovery)
**Description:** Simulation of an attacker collecting information about the local system and the Active Directory domain.

## Lab Execution

Executed through a PowerShell script:
`whoami /all; net user /domain; net group "Domain Admins" /domain; systeminfo`

## Results

* **SPL Triggered:** True Positive
* **KQL Triggered:** True Positive
* **Detected Events:** EventCode 4688 (Windows Security) or EventID 1 (Sysmon).
* **Notes:** The detection was triggered by grouping the execution of these tools within a short time period.
