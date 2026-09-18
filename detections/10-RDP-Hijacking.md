# Detection of RDP Session Hijacking via Tscon

### Description
This rule detects attempts to hijack a disconnected or active Remote Desktop (RDP) session using the native Windows utility `tscon.exe`. Attackers with SYSTEM privileges use this technique to take over sessions belonging to other users (often domain administrators), completely bypassing the need to know or crack the victim's password. The key indicator is the use of the `/dest:` parameter to redirect the target session.

## MITRE ATT&CK
* **Tactic:** Lateral Movement (TA0008)
* **Technique:** Remote Services (T1021)
* **Sub-technique:** Remote Desktop Protocol (T1021.001)

## Alert Metadata
* **Severity:** Critical
* **Confidence:** High
* **Impact:** High

### SPL Query
```splunk
index=wineventlog EventCode=4688 "tscon"

| eval Command_Check=coalesce(Process_Command_Line, CommandLine, _raw)
| regex Command_Check="(?i)tscon.*[\/-]dest\s*:"
| eval User_Creator=mvindex(Account_Name, 0)
| table _time, host, User_Creator, Command_Check

```

### Possible False Positives
* Third-party remote IT management software that relies on `tscon.exe`.
  
---

### Triage Notes / Recommended Actions

1. **User Analysis (`Account_Name`)**
    To perform this attack successfully without knowing the victim's password, the attacker must run the command as `NT AUTHORITY\SYSTEM`. If the source account is `SYSTEM`, the alert has a critical severity level (Severity: Critical).

2. **Logon Correlation (EventCode 4778)**
   In addition to the command line, look for EventCode 4778 (A session was reconnected to a Window Station) within the same timeframe to confirm that the hijacking was successful and to determine which account was compromised.

3. **Containment**
   Isolate the target server. Forcibly disconnect the hijacked user and immediately reset their credentials, as the attacker might have extracted them once they gained access to the desktop.
