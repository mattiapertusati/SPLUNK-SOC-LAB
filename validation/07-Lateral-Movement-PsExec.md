## 🧪 Validation Report: Lateral Movement via PsExec

**Fase della Kill Chain:** Lateral Movement / Execution
**Tecnica MITRE ATT&CK:** [T1569.002 - System Services: Service Execution](https://attack.mitre.org/techniques/T1569/002/)

### 1. Attack Execution
* **Strumento:** Atomic Red Team
* **Test Eseguito:** Test 2 - Use PsExec to execute a command on a remote host
* **Comando Lanciato:**
  ```powershell
  Invoke-AtomicTest T1569.002 -TestNumbers 2 -PathToAtomicsFolder "C:\AtomicRedTeam\atomics"
  ```
<img width="809" height="124" alt="Screenshot 2026-06-11 114352" src="https://github.com/user-attachments/assets/ac6ebfba-b741-4067-8d4e-c454c049101a" />

### 2. Telemetry & Logs

* **Sorgente Dati:** Windows Security Event Log / System Log
* **EventID Atteso:** 4697 (Security) e 7045 (System) - A service was installed in the system.

<img width="903" height="1097" alt="Screenshot 2026-06-11 114419" src="https://github.com/user-attachments/assets/5375bfac-fdb0-4184-a94a-42f87d7403c0" />

### 3. Detection & Validation

* **Nome Regola:** PsExec Service Installation
* **Risultato Test:** ✅ Triggered = YES
* **Falsi Positivi:** Moderati. PsExec è un tool di amministrazione Sysinternals legittimo. Tuttavia, in ambienti maturi, il suo utilizzo dovrebbe essere dismesso a favore di WinRM/PowerShell Remoting, rendendo ogni avvio di `PSEXESVC` altamente sospetto.

### 🔴 Splunk (SPL)
```spl
index=wineventlog (EventCode=7045 OR EventCode=4697) ("*PSEXESVC*" OR "*PsExec execution service*")
| table _time, host, EventCode, Account_Name, Service_Name, Service_File_Name
```

### 🔵 Microsoft Sentinel (KQL)
```kql
SecurityEvent
| where EventID == 4697 and (ServiceName =~ "PSEXESVC" or ServiceFileName has "PSEXESVC.exe")
<img width="809" height="124" alt="Screenshot 2026-06-11 114352" src="https://github.com/user-attachments/assets/5b69f22c-80db-4907-a249-bfa2070a80d3" />
| project TimeGenerated, Computer, Account, ServiceName, ServiceFileName, ServiceType
```

### 🟡 Sigma Rule (Agnostic)
Vedi il file **lateral_movement_psexec.yml** nel repository per la regola completa.

### 4. Validation Results

1. **Attack Executed:** YES
2. **Logs Generated:** YES
3. **Detection Triggered:** YES
4. **False Positives:** Moderati.

<img width="1175" height="335" alt="Screenshot 2026-06-11 114440" src="https://github.com/user-attachments/assets/cd2b0ef6-2fd8-475b-bff9-73b892b21db4" />

