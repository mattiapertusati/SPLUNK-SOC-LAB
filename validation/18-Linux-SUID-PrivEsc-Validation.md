# Validation Report: Detection 18 - Linux SUID Discovery

## Simulated Scenario

**MITRE ATT&CK:** T1548.001 (Abuse Elevation Control Mechanism: Setuid)
**Description:** Search for binaries with SUID permissions on Linux machines for Privilege Escalation.

## Lab Execution

Executed on a Linux terminal (Ubuntu):
`find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null`

## Results

* **SPL Triggered:** True Positive
* **KQL Triggered:** True Positive
* **Detected Events:** DeviceProcessEvents / Linux Auditd (bash with find s-bit parameters).
