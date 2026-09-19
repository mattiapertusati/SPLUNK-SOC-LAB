## Validation Report: Clear Windows Event Logs

**Kill Chain Phase:** Defense Evasion
**MITRE ATT&CK Technique:** [T1070.001 - Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001/)

### 1. Attack Execution

* **Tool:** Native OS Command / Atomic Red Team
* **Command Executed:**

  ```powershell
  wevtutil cl Security
  ```

<img width="790" height="102" alt="Screenshot 2026-06-09 220921" src="https://github.com/user-attachments/assets/193d38cf-ba69-49ee-ac2a-e088e3c9fdf0" />

### 2. Telemetry & Logs

* **Data Source:** Windows Security Event Log
* **Expected EventID:** 1102 (The audit log was cleared)

<img width="899" height="879" alt="Screenshot 2026-06-10 103243" src="https://github.com/user-attachments/assets/e8443fdc-51d8-4aca-bd10-1998f61e068b" />

### 3. Detection & Validation

* **Rule Name:** Security Event Log Cleared
* **Test Result:** Triggered = YES
* **False Positives:** Low. Clearing the Security log is an extremely unusual action that should only be performed during exceptional maintenance operations and must be strictly monitored.

### Splunk (SPL)

```spl id="a4f6q9"
index=wineventlog (EventCode=1102 OR EventCode=104)
| eval User_Responsible=coalesce(SubjectUserName, Account_Name, UserID, "SYSTEM/Unknown")
| table _time, host, EventCode, User_Responsible, TaskCategory
```

### Microsoft Sentinel (KQL)

```kql id="e7k2m5"
SecurityEvent
| where EventID == 1102
| project TimeGenerated, Computer, Account, Activity
```

### Sigma Rule (Agnostic)

See the **log_clearing.yml** file in the repository for the complete rule.

### 4. Validation Results

* **Attack Executed:** YES
* **Logs Generated:** YES (Validated using historical telemetry)
* **Detection Triggered:** YES
* **False Positives:** Low.

<img width="1192" height="714" alt="Screenshot 2026-06-10 103302" src="https://github.com/user-attachments/assets/d78363ea-f625-4188-99ed-de80a3b203f2" />
