# Validation Report: Detection 18 - Linux SUID Discovery

## 🎯 Scenario Simulato
**MITRE ATT&CK:** T1548.001 (Abuse Elevation Control Mechanism: Setuid)
**Descrizione:** Ricerca di binari con permessi SUID su macchine Linux per Privilege Escalation.

## 💥 Esecuzione in Lab
Eseguito su terminale Linux (Ubuntu):
`find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null`

## 📊 Risultati
* **SPL Triggered:** ✅ True Positive
* **KQL Triggered:** ✅ True Positive
* **Eventi Rilevati:** DeviceProcessEvents / Linux Auditd (bash con parametri find s-bit).
