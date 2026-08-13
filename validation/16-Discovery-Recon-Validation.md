# Validation Report: Detection 16 - Discovery Recon

## 🎯 Scenario Simulato
**MITRE ATT&CK:** TA0007 (Discovery)
**Descrizione:** Simulazione di un attaccante che raccoglie informazioni sul sistema locale e sul dominio Active Directory.

## 💥 Esecuzione in Lab
Eseguito tramite script PowerShell:
`whoami /all; net user /domain; net group "Domain Admins" /domain; systeminfo`

## 📊 Risultati
* **SPL Triggered:** ✅ True Positive
* **KQL Triggered:** ✅ True Positive
* **Eventi Rilevati:** EventCode 4688 (Windows Security) o EventID 1 (Sysmon).
* **Note:** La detection è scattata raggruppando l'esecuzione ravvicinata di questi tool.
