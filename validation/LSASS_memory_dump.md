## 🧪 Validation Report: LSASS Memory Dump

**Fase della Kill Chain:** Credential Access
**Tecnica MITRE ATT&CK:** [T1003.001 - OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)

### 1. Attack Execution
* **Strumento:** Atomic Red Team
* **Test Eseguito:** Test 1 - Dump LSASS.exe using comsvcs.dll
* **Comando Lanciato:**
  
  ```powershell
  Invoke-AtomicTest T1003.001 -TestNumbers 1 -PathToAtomicsFolder "C:\AtomicRedTeam\atomics"
  ```
  
Screenshot Esecuzione:
(Inserisci qui lo screenshot del terminale PowerShell)

### 2. Telemetry & Logs

* Sorgente Dati: Sysmon / PowerShell Operational
* EventID Attesi: 10 (Sysmon) o 4104 (PowerShell)

Screenshot Log Crudo:
(Inserisci qui lo screenshot di Splunk che mostra il log grezzo arrivato)

### 3. Detection & Validation

* Nome Regola: LSASS Memory Dump via PowerShell
* Risultato Test: ✅ Triggered = YES
* Falsi Positivi: NO (La regola è strettamente legata a comsvcs.dll)

Screenshot Alert:
(Inserisci qui lo screenshot dell'allarme scattato su Splunk o sulla Dashboard)
