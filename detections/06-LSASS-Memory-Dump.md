# Detection of LSASS Memory Dumping via Comsvcs.dll

### Description
This rule detects attempts to extract clear-text credentials and password hashes from the memory of the `LSASS` (Local Security Authority Subsystem Service) system process. The attack uses a "Living off the Land" technique, exploiting the legitimate Windows binary `rundll32.exe` to call the exported MiniDump function inside the `comsvcs.dll` system library. This allows the attacker to bypass basic restrictions and save a dump file (usually `.dmp`) for offline password extraction using tools like Mimikatz.

## MITRE ATT&CK
* **Tactic:** Credential Access (TA0006)
* **Technique:** OS Credential Dumping (T1003)
* **Sub-technique:** LSASS Memory (T1003.001)
* 
## Alert Metadata

Note on Severity: LSASS dumping is one of the most serious indicators in a corporate network (it often precedes ransomware). If successful, the attacker has the keys to the kingdom. For this reason, the Severity must be raised to the maximum level.

* **Severity:** Critical
* **Confidence:** High
* **Impact:** Critical

### SPL Query

```splunk
index=sysmon EventCode=1 "comsvcs.dll" ("MiniDump" OR "#24")
| table _time, host, User, CommandLine
```

### Possible False Positives
* EDR/Antivirus software performing memory dumps for analysis.
* Dumps created for troubleshooting and/or system crashes.

---

### Triage Notes / Recommended Actions

1. **Command Line Analysis (`CommandLine`)**
   Verify the path where the dump file is saved. If the file is written to temporary directories (for example, `C:\Windows\Temp\`, `C:\Users\...\AppData\Local\Temp\`), the activity is almost certainly malicious.

2. **Privilege Verification**
   This attack requires Administrator privileges (specifically `SeDebugPrivilege`). Immediately investigate which account ran the command: check if it is a compromised standard user account that performed a `Privilege Escalation`, or a legitimate administrative account with stolen credentials.
   
3. **Containment (Remediation)**
   Consider the host as critically compromised. Isolate the machine from the network immediately. Since the attacker might have already extracted and decrypted the passwords, forcing a credential reset for all accounts that recently logged into that endpoint is mandatory.
