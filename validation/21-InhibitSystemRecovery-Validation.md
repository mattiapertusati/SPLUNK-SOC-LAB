# Validation Report: Detection 21 - Inhibit System Recovery

## 🎯 Scenario Simulato
**MITRE ATT&CK:** T1490 (Inhibit System Recovery)
**Descrizione:** Cancellazione delle Volume Shadow Copies, tecnica standard utilizzata dai Ransomware per impedire il ripristino del sistema.

## 💥 Esecuzione in Lab
Eseguito via vssadmin:
`vssadmin.exe Delete Shadows /All /Quiet`

## 📊 Risultati
* **SPL Triggered:** ✅ True Positive
* **KQL Triggered:** ✅ True Positive
* **Eventi Rilevati:** EventCode 4688 (Process Creation per vssadmin / wbadmin).
