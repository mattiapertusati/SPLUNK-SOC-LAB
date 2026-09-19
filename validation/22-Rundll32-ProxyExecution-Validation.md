# Validation Report: Detection 22 - Rundll32 Proxy Execution

## Simulated Scenario

**MITRE ATT&CK:** T1218.011 (System Binary Proxy Execution: Rundll32)
**Description:** Abuse of the legitimate system binary rundll32.exe to load and execute malicious payloads while evading security controls.

## Lab Execution

Execution of a simulated malicious DLL:
`rundll32.exe C:\Temp\malicious.dll,EntryPoint`

## Results

* **SPL Triggered:** True Positive
* **KQL Triggered:** True Positive
* **Detected Events:** EventCode 1 (Sysmon) / 4688 (Windows Security), monitoring `rundll32.exe` with suspicious extensions or anomalous paths.
