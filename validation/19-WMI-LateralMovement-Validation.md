# Validation Report: Detection 19 - WMI Execution

## Simulated Scenario

**MITRE ATT&CK:** T1047 (Windows Management Instrumentation)
**Description:** Use of WMI (wmic) to execute processes on a remote host (Lateral Movement).

## Lab Execution

Executed through CMD:
`wmic /node:"192.168.1.50" process call create "cmd.exe /c powershell.exe -c Get-Process"`

## Results

* **SPL Triggered:** True Positive
* **KQL Triggered:** True Positive
* **Detected Events:** `WmiPrvSE.exe` process spawning `cmd.exe`.
