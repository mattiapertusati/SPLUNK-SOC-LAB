## Validation Report: Scheduled Task Persistence

**Kill Chain Phase:** Persistence / Privilege Escalation
**MITRE ATT&CK Technique:** [T1053.005 - Scheduled Task/Job: Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)

### 1. Attack Execution

* **Tool:** Atomic Red Team
* **Test Performed:** Test 1 - Scheduled Task Startup Script
* **Command Executed:**

  ```powershell
  Invoke-AtomicTest T1053.005 -TestNumbers 1 -PathToAtomicsFolder "C:\AtomicRedTeam\atomics"
  ```

  <img width="809" height="152" alt="Screenshot 2026-06-11 114235" src="https://github.com/user-attachments/assets/938bffb8-3c09-4f93-b00f-4c134a39cde0" />

### 2. Telemetry & Logs

* **Data Source:** Windows Security Event Log
* **Expected EventID:** 4698 (A scheduled task was created)

<img width="899" height="1206" alt="Screenshot 2026-06-11 114310" src="https://github.com/user-attachments/assets/c46caf74-0f8d-4779-a218-0adbf2f3e737" />

### 3. Detection & Validation

* **Rule Name:** Malicious Scheduled Task Creation
* **Test Result:** Triggered = YES
* **False Positives:** Moderate. Many legitimate software applications (e.g., updaters) create scheduled tasks. The rule becomes more accurate when filtering for unusual paths (e.g., C:\Windows\Temp) or suspicious executables.

### Splunk (SPL)

```spl id="c6c1yf"
index=wineventlog EventCode=4698
| rex field=_raw "<Command>(?<Task_Command>[^<]+)</Command>"
| rex field=_raw "<Arguments>(?<Task_Arguments>[^<]+)</Arguments>"
| table _time, host, Account_Name, Task_Name, Task_Command, Task_Arguments
```

### Microsoft Sentinel (KQL)

```kql id="w5w4u1"
SecurityEvent
| where EventID == 4698
| extend Task_Command = extract(@"<Command>([^<]+)</Command>", 1, EventData)
| extend Task_Arguments = extract(@"<Arguments>([^<]+)</Arguments>", 1, EventData)
| project TimeGenerated, Computer, Account, TaskName = Activity, Task_Command, Task_Arguments
```

### Sigma Rule (Agnostic)

See the **scheduled_task_creation.yml** file in the repository for the complete rule.

### 4. Validation Results

1. **Attack Executed:** YES
2. **Logs Generated:** YES
3. **Detection Triggered:** YES
4. **False Positives:** Moderate.

<img width="1181" height="333" alt="Screenshot 2026-06-11 114322" src="https://github.com/user-attachments/assets/bb7a22b0-03ca-4a5c-bf54-779d24cd0597" />
