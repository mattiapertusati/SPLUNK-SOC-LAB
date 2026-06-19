# 🛡️ Detection Rules Library (SPL)

Benvenuto nella libreria centrale delle regole di rilevamento di questo laboratorio. Tutte le query presenti in questa directory sono scritte in **Splunk Processing Language (SPL)** e sono progettate per un ambiente SOC Enterprise.

Ogni file `.md` elencato qui sotto contiene non solo la logica di ricerca, ma un **Detection Blueprint** completo di:
* Mappatura MITRE ATT&CK
* Metadati di Severity e Confidence
* Analisi dei Falsi Positivi
* **Playbook di Triage** con azioni consigliate per l'analista L1.

## 🗂️ Indice delle Detection

* 📄 [01 - Encoded PowerShell Command Execution](01-Encoded-Powershell.md)
* 📄 [02 - Local User Creation](02-User-Creation.md)
* 📄 [03 - Local Privilege Escalation (UAC)](03-Privilege-Escalation.md)
* 📄 [04 - Windows Defender Evasion](04-Defender-Evasion.md)
* 📄 [05 - Scheduled Task Persistence](05-Scheduled-Task-Persistence.md)
* 📄 [06 - OS Credential Dumping: LSASS Memory](06-LSASS-Memory-Dump.md)
* 📄 [07 - Lateral Movement via PsExec](07-Lateral-Movement-PsExec.md)
* 📄 [08 - Firewall Manipulation (Netsh)](08-Firewall-Manipulation.md)
* 📄 [09 - Clearing Event Logs](09-Clearing-Event-Logs.md)
* 📄 [10 - RDP Session Hijacking (Tscon)](10-RDP-Hijacking.md)
* 🔗 [11 - Correlation Credential Theft](11-Correlation-Domain-Compromise.md)
* 🔗 [12 - Correlation Credential Theft](12-Correlation-Credential-Theft.md)
* 🔗 [13 - Correlation Lateral Persistence](13-Correlation-Lateral-Persistence.md)
* 🔗 [14 - Correlation Ransomware Exfiltration](14-Correlation-Ransomware-Exfiltration.md)
* 🔗 [15 - Correlation Phishing InitialAccess](15-Correlation-Phishing-InitialAccess.md)
* 📄 [16 - Discovery Recon](16-Discovery-Recon.md)

---
**Nota per l'Auditor/Recruiter:** Clicca su uno qualsiasi dei link sopra per navigare direttamente alla logica di rilevamento e al relativo playbook operativo.
