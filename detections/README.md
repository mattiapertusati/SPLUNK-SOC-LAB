# Detection Rules Library (SPL)

Welcome to the central library of detection rules for this laboratory. All the queries present in this directory are written in **Splunk Processing Language (SPL)** and are designed for an Enterprise SOC environment.

Every `.md` file listed below contains not only the search logic, but a complete **Detection Blueprint** including:
* MITRE ATT&CK Mapping
* Severity and Confidence Metadata
* False Positives Analysis
* **Triage Playbook** with recommended actions for the L1 analyst.

## Detection Index

* [01 - Encoded PowerShell Command Execution](01-Encoded-PowerShell.md)
* [02 - Local User Creation](02-User-Creation.md)
* [03 - Local Privilege Escalation (UAC)](03-Privilege-Escalation.md)
* [04 - Windows Defender Evasion](04-Defender-Evasion.md)
* [05 - Scheduled Task Persistence](05-Scheduled-Task-Persistence.md)
* [06 - OS Credential Dumping: LSASS Memory](06-LSASS-Memory-Dump.md)
* [07 - Lateral Movement via PsExec](07-Lateral-Movement-PsExec.md)
* [08 - Firewall Manipulation (Netsh)](08-Firewall-Manipulation.md)
* [09 - Clearing Event Logs](09-Clearing-Event-Logs.md)
* [10 - RDP Session Hijacking (Tscon)](10-RDP-Hijacking.md)
* [11 - Correlation Credential Theft](11-Correlation-Domain-Compromise.md)
* [12 - Correlation Credential Theft](12-Correlation-Credential-Theft.md)
* [13 - Correlation Lateral Persistence](13-Correlation-Lateral-Persistence.md)
* [14 - Correlation Ransomware Exfiltration](14-Correlation-Ransomware-Exfiltration.md)
* [15 - Correlation Phishing InitialAccess](15-Correlation-Phishing-InitialAccess.md)
* [16 - Discovery Recon](16-Discovery-Recon.md)
* [17 - Kerberoasting CredentialAccess](17-Kerberoasting-CredentialAccess.md)
* [18 - Linux SUID PrivEsc](18-Linux-SUID-PrivEsc.md)
* [19 - WMI LateralMovement](19-WMI-LateralMovement.md)
* [20 - TokenImpersonation PrivEsc](20-TokenImpersonation-PrivEsc.md)
* [21 - InhibitSystemRecovery](21-InhibitSystemRecovery.md)
* [22 - Rundll32-ProxyExecution](22-Rundll32-ProxyExecution.md)
---
**Note for the Auditor/Recruiter:** Click on any of the links above to navigate directly to the detection logic and its related operational playbook.
