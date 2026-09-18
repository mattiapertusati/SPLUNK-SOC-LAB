# Multi-Stage Attack: Phishing Initial Access & C2

### Description
This **Advanced Correlation** rule tracks the classic initial access vector via Spearphishing. The alert triggers if, within a maximum window of 15 minutes on the same machine, an Office suite application (Word or Excel) abnormally generates a command-line child process (CMD or PowerShell), and the latter subsequently starts an external network connection to download the second-stage payload (C2).

## MITRE ATT&CK
* **Tactic:** Initial Access (TA0001), Execution (TA0002), Command and Control (TA0011)
* **Technique:** Phishing: Spearphishing Attachment (T1566.001), Command and Scripting Interpreter (T1059), Application Layer Protocol (T1071)

## Alert Metadata
* **Severity:** HIGH
* **Confidence:** High (Office launching PowerShell and connecting to the internet is almost always a malicious activity)
* **Impact:** High

### SPL Query (Correlation Engine)
```splunk
(index=wineventlog OR index=sysmon)
(
  (EventCode=4688 OR EventCode=1) ("*winword.exe*" OR "*excel.exe*") ("*cmd.exe*" OR "*powershell.exe*")
) OR (
  EventCode=3 ("*powershell.exe*" OR "*cmd.exe*")
)
| transaction host maxspan=15m
| search ("*winword.exe*" OR "*excel.exe*") AND ("*cmd.exe*" OR "*powershell.exe*") AND EventCode=3
| eval Attack_Chain="CRITICAL ALERT: Macro Execution (Office) -> Shell Launch -> C2 Connection"
| table _time, host, duration, Attack_Chain
```

### Triage & Recommended Actions
This event indicates the exact moment of "Patient Zero".

1. **Evidence Retrieval:** Locate the original malicious file (.docx, .docm, .xlsx) opened by the user and isolate it.

2. **Network Analysis:** Extract the IP address or domain contacted during stage 2 of the attack (EventCode 3) and block it on the corporate proxy/firewall to prevent further payload downloads.

3. **Global Scan:** Search the email logs to check if the same attached file was sent to other employees in the company.
