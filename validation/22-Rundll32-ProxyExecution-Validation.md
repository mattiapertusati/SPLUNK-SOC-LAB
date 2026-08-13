# Validation Report: Detection 22 - Rundll32 Proxy Execution

## 🎯 Scenario Simulato
**MITRE ATT&CK:** T1218.011 (System Binary Proxy Execution: Rundll32)
**Descrizione:** Abuso del binario legittimo di sistema rundll32.exe per caricare ed eseguire payload malevoli eludendo i controlli.

## 💥 Esecuzione in Lab
Esecuzione di una DLL malevola simulata:
`rundll32.exe C:\Temp\malicious.dll,EntryPoint`

## 📊 Risultati
* **SPL Triggered:** ✅ True Positive
* **KQL Triggered:** ✅ True Positive
* **Eventi Rilevati:** EventCode 1 (Sysmon) / 4688 (Windows Security) monitorando `rundll32.exe` con estensioni sospette o path anomali.
