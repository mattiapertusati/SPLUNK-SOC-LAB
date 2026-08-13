# Validation Report: Detection 20 - Token Impersonation

## 🎯 Scenario Simulato
**MITRE ATT&CK:** T1134.001 (Token Impersonation/Theft)
**Descrizione:** Creazione di un processo con permessi elevati rubando o impersonando il token di accesso di un altro utente (es. SYSTEM).

## 💥 Esecuzione in Lab
Simulato con modulo meterpreter (getsystem) / incognito o tool custom. Generazione di accessi con privilegi speciali.

## 📊 Risultati
* **SPL Triggered:** ✅ True Positive
* **KQL Triggered:** ✅ True Positive
* **Eventi Rilevati:** EventCode 4672 (Special privileges assigned to new logon).
