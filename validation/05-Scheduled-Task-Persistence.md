## 🧪 Validation Report: Scheduled Task Persistence

**Fase della Kill Chain:** Persistence / Privilege Escalation
**Tecnica MITRE ATT&CK:** [T1053.005 - Scheduled Task/Job: Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)

### 1. Attack Execution
* **Strumento:** Atomic Red Team
* **Test Eseguito:** Test 1 - Scheduled Task Startup Script
* **Comando Lanciato:**
  
  ```powershell
  Invoke-AtomicTest T1053.005 -TestNumbers 1 -PathToAtomicsFolder "C:\AtomicRedTeam\atomics"
  ```
  <img width="809" height="152" alt="Screenshot 2026-06-11 114235" src="https://github.com/user-attachments/assets/938bffb8-3c09-4f93-b00f-4c134a39cde0" />

### 2. Telemetry & Logs
* **Sorgente Dati:** Windows Security Event Log
* **EventID Atteso:** 4698 (A scheduled task was created)

<img width="899" height="1206" alt="Screenshot 2026-06-11 114310" src="https://github.com/user-attachments/assets/c46caf74-0f8d-4779-a218-0adbf2f3e737" />

### 3. Detection & Validation
* **Nome Regola:** Malicious Scheduled Task Creation
* **Risultato Test:** ✅ Triggered = YES
* **Falsi Positivi:** Moderati. Molti software legittimi (es. updater) creano task pianificati. La regola acquista precisione filtrando per percorsi anomali (es. C:\Windows\Temp) o eseguibili sospetti.

### 🔴 Splunk (SPL)

```spl
index=wineventlog EventCode=4698
| rex field=_raw "<Command>(?<Task_Command>[^<]+)</Command>"
| rex field=_raw "<Arguments>(?<Task_Arguments>[^<]+)</Arguments>"
| table _time, host, Account_Name, Task_Name, Task_Command, Task_Arguments
```

### 🔵 Microsoft Sentinel (KQL)

```kql
SecurityEvent
| where EventID == 4698
| extend Task_Command = extract(@"<Command>([^<]+)</Command>", 1, EventData)
| extend Task_Arguments = extract(@"<Arguments>([^<]+)</Arguments>", 1, EventData)
| project TimeGenerated, Computer, Account, TaskName = Activity, Task_Command, Task_Arguments
```

### 🟡 Sigma Rule (Agnostic)
Vedi il file **scheduled_task_creation.yml** nel repository per la regola completa.

### 4. Validation Results
1. **Attack Executed:** YES
2. **Logs Generated:** YES
3. **Detection Triggered:** YES
4. **False Positives:** Moderati.

<img width="1181" height="333" alt="Screenshot 2026-06-11 114322" src="https://github.com/user-attachments/assets/bb7a22b0-03ca-4a5c-bf54-779d24cd0597" />

