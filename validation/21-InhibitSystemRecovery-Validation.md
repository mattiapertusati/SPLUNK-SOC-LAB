# Validation Report: Detection 21 - Inhibit System Recovery

## Simulated Scenario

**MITRE ATT&CK:** T1490 (Inhibit System Recovery)
**Description:** Deletion of Volume Shadow Copies, a standard technique used by Ransomware to prevent system recovery.

## Lab Execution

Executed using vssadmin:
`vssadmin.exe Delete Shadows /All /Quiet`

## Results

* **SPL Triggered:** True Positive
* **KQL Triggered:** True Positive
* **Detected Events:** EventCode 4688 (Process Creation for vssadmin / wbadmin).
