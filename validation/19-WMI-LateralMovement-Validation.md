# Validation Report: Detection 19 - WMI Execution

## 🎯 Scenario Simulato
**MITRE ATT&CK:** T1047 (Windows Management Instrumentation)
**Descrizione:** Utilizzo di WMI (wmic) per eseguire processi su un host remoto (Lateral Movement).

## 💥 Esecuzione in Lab
Eseguito tramite CMD:
`wmic /node:"192.168.1.50" process call create "cmd.exe /c powershell.exe -c Get-Process"`

## 📊 Risultati
* **SPL Triggered:** ✅ True Positive
* **KQL Triggered:** ✅ True Positive
* **Eventi Rilevati:** Processo `WmiPrvSE.exe` che spawna `cmd.exe`.
