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
  
<img width="1259" height="762" alt="Screenshot 2026-06-09 172303" src="https://github.com/user-attachments/assets/5c61bde9-679d-41a1-a38f-3e29ea1fec3c" />

### 2. Telemetry & Logs

* Sorgente Dati: Sysmon / PowerShell Operational
* EventID Attesi: 10 (Sysmon) o 4104 (PowerShell)

<img width="956" height="1176" alt="Screenshot 2026-06-09 220145" src="https://github.com/user-attachments/assets/5d7941f9-78fa-43b6-a57b-049ff151627e" />

### 3. Detection & Validation

* Nome Regola: LSASS Memory Dump via PowerShell
* Risultato Test: ✅ Triggered = YES
* Falsi Positivi: NO (La regola è strettamente legata a comsvcs.dll)
  
<img width="1209" height="381" alt="Screenshot 2026-06-09 220159" src="https://github.com/user-attachments/assets/52a65241-c0aa-464a-8ae5-b6ee0be4ee73" />
