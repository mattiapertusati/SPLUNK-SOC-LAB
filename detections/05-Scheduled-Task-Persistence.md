# Detection of Scheduled Task Creation for Persistence

### Description
This rule detects the creation of a new scheduled task on the system. Attackers regularly exploit this technique to ensure persistence within the infrastructure, allowing malware or backdoors to run automatically at preset intervals or when the computer restarts, even if the initial access is removed.

## MITRE ATT&CK
* **Tactic:** Persistence (TA0003)
* **Technique:** Scheduled Task/Job (T1053)
* **Sub-technique:** Scheduled Task (T1053.005)
* 
## Alert Metadata
* **Severity:** Medium
* **Confidence:** High
* **Impact:** High

(Note: The Severity is set to Medium because creating Scheduled Tasks is a very frequent activity of the operating system and legitimate software. The Impact remains High because, if the action is malicious, it guarantees the attacker persistent access or code execution with high privileges).

### SPL Query
```splunk
index=wineventlog EventCode=4698
| rex field=_raw "<Command>(?<Task_Command>[^<]+)</Command>"
| rex field=_raw "<Arguments>(?<Task_Arguments>[^<]+)</Arguments>"
| table _time, host, Account_Name, Task_Name, Task_Command, Task_Arguments
```

### Possible False Positives
* Installations or updates that require scheduling.
* Maintenance and/or control scripts that require repetition (scheduling).

---

### Triage Notes / Recommended Actions

1. **Executable Path Analysis ('Task_Command')**
Carefully inspect the path of the file started by the task. The execution of binaries located in temporary folders or folders writable by users (for example, 'C:\Windows\Temp\', 'C:\Users\...\AppData\') is a very strong indicator of malicious activity.

2. **Task Name Verification ('Task_Name')**
Attackers often use Masquerading techniques by naming tasks similarly to critical Windows services (for example, 'Windows_Update_Helper', 'MfeSysFlt'). Compare the name with internal documentation and check for anomalies in characters or the path.   

3. **Author Investigation (Account_Name)**
   Verify if the account that created the task is authorized to do so. If the action does not match a maintenance window or an approved ticket, proceed with isolating the host for containment.
