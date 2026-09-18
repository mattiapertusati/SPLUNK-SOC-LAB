# Detection of Event Log Clearing

### Description
This rule detects the manual or scripted clearing of Windows event logs (Security or System). Attackers use this technique, known as "Scorched Earth", in the final stages of an intrusion to eliminate traces of their activities (such as user creations, lateral movements, or command executions), making it extremely difficult for Incident Response teams to reconstruct the attack chain.

## MITRE ATT&CK
* **Tactic:** Defense Evasion (TA0005)
* **Technique:** Indicator Removal (T1070)
* **Sub-technique:** Clear Windows Event Logs (T1070.001)

## Alert Metadata
* **Severity:** Critical
* **Confidence:** High
* **Impact:** High

(Note: The Severity is Critical because there are no business or ordinary IT administration reasons to clear the entire Security or System log. When this happens, it is almost always an attack or an administrator trying to hide a serious mistake).

### SPL Query
```splunk
index=wineventlog (EventCode=1102 OR EventCode=104)
| eval User_Responsible=coalesce(SubjectUserName, Account_Name, UserID, "SYSTEM/Unknown")
| table _time, host, EventCode, User_Responsible, TaskCategory
```

### Possible False Positives
* Approved automatic cleanup scripts.
* Troubleshooting and/or remediation activities.

---

### Triage Notes / Recommended Actions

1. **User Analysis (`Account_Name`)**
    Immediately verify who triggered the event. Clearing logs requires administrative privileges. If it is a standard user (Possible Privilege Escalation) or an administrator acting out of hours, consider the event a **Critical Alert**.

2. **Search for the Clearing Method**
   Look in previous logs (EventCode 4688 or Sysmon 1) for the use of commands like `wevtutil cl`, `Remove-EventLog` (PowerShell), or `Clear-EventLog` in adjacent time windows.

3. **Containment**
   Isolate the affected endpoint immediately. Consider the host as severely compromised. Start Incident Response procedures and begin forensic triage on network logs, as local logs are no longer reliable.
