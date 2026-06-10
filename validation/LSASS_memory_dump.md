## 🧪 Validation Report: LSASS Memory Dump

**Fase della Kill Chain:** Credential Access
**Tecnica MITRE ATT&CK:** [T1003.001 - OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)

### 1. Attack Execution
* **Strumento:** Atomic Red Team
* **Test Eseguito:** Test 2 - Dump LSASS.exe using comsvcs.dll
* **Comando Lanciato:**
  
  ```powershell
  Invoke-AtomicTest T1003.001 -TestNumbers 2 -PathToAtomicsFolder "C:\AtomicRedTeam\atomics"
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

### 🔴 Splunk (SPL)

```spl
index=sysmon EventCode=1 "comsvcs.dll" ("MiniDump" OR "#24")
| table _time, host, User, CommandLine
```

### 🔵 Microsoft Sentinel (KQL)

```kql
DeviceProcessEvents
| where FileName =~ "rundll32.exe"
| where ProcessCommandLine has "comsvcs.dll" and (ProcessCommandLine has "MiniDump" or ProcessCommandLine has "#24")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
```

### 🟡 Sigma Rule (Agnostic)

Vedi il file **lsass_memory_dump.yml** nel repository per la regola completa.

### 4. Validation Results

1. **Attack Executed:** YES
2. **Logs Generated:** YES
3. **Detection Triggered:** YES
4. **False Positives:** Bassi. L'utilizzo di comsvcs.dll accoppiato a MiniDump da riga di comando è altamente anomalo per le normali operazioni di amministrazione di sistema e quasi sempre indicativo di attività malevola o di un test autorizzato.
  
<img width="1209" height="381" alt="Screenshot 2026-06-09 220159" src="https://github.com/user-attachments/assets/52a65241-c0aa-464a-8ae5-b6ee0be4ee73" />

