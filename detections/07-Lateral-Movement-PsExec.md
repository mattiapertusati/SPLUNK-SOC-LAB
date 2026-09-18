# Detection of Lateral Movement via PsExec

### Description
This rule detects the installation of a new system service associated with PsExec, a legitimate utility from the Microsoft Sysinternals suite. Although designed for IT administration purposes, PsExec is widely abused by attackers (including Ransomware groups) to execute commands or deploy payloads on remote machines within the domain. Running PsExec remotely involves writing the `PSEXESVC.exe` binary to the `ADMIN$` share and subsequently creating the service of the same name to execute with SYSTEM privileges.

## MITRE ATT&CK
* **Tactic:** Lateral Movement (TA0008), Execution (TA0002)
* **Technique:** Services (T1021) or Command and Scripting Interpreter (T1059)
* **Sub-technique:** SMB/Windows Admin Shares (T1021.002)
  
## Alert Metadata

* **Severity:** High
* **Confidence:** High
* **Impact:** High

(Note: The Severity is set to High instead of Critical only because PsExec is an official Microsoft tool heavily used by IT administrators. It becomes Critical the moment triage confirms that the user is not an admin or the file name is altered).

### SPL Query
```splunk
index=wineventlog (EventCode=7045 OR EventCode=4697) ("*PSEXESVC*" OR "*PsExec execution service*")
| table _time, host, EventCode, Account_Name, Service_Name, Service_File_Name
```

### Possible False Positives
* Legitimate use of PsExec by system administrators.
* Authorized vulnerability scans that use PsExec.

---

### Triage Notes / Recommended Actions

1. **User Verification (`Account_Name`)**
   Check which account installed the service. If the account belongs to a standard user (who should not have remote administration privileges) or if the action occurs outside of normal working hours, the alert must be considered critical.

2. **Binary Analysis (`Service_File_Name`)**
   Although the default name is `PSEXESVC.exe`, attackers can rename the service (using the `-r` option of PsExec). Pay close attention to services with random names (for example, `x7gf9.exe`) installed in the `C:\Windows\` directory.   

3. **Related Hunting (Network Logs)**
   Look for inbound connections on port 445 (SMB) to the compromised host within the same timeframe to identify the source machine from which the attack started ("Patient Zero").

4. **Containment**
   Isolate both the target host and the source host. Immediately revoke the credentials of the compromised account used for the lateral movement.
