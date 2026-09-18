# Multi-Stage Attack: Ransomware Data Staging & Impact

### Description
This **Advanced Correlation** rule tracks the final and most devastating stages of a Ransomware attack. The alert triggers if, within 60 minutes on the same machine, an attacker compresses sensitive files into an archive (Data Staging), uses command-line network utilities to exfiltrate the archive to an external server, and finally, destroys local backups (Shadow Copies) to prevent data recovery.

## MITRE ATT&CK
* **Tactic:** Collection (TA0009), Exfiltration (TA0010), Impact (TA0040)
* **Technique:** Archive Collected Data (T1560), Exfiltration Over Alternative Protocol (T1048), Inhibit System Recovery (T1490)

## Alert Metadata
* **Severity:** CRITICAL
* **Confidence:** High
* **Impact:** Critical

### SPL Query (Correlation Engine)
```splunk
(index=wineventlog OR index=sysmon)
(
  (EventCode=4688 OR EventCode=1) ("*7z.exe*" OR "*WinRAR.exe*")
) OR ( 
  (EventCode=4688 OR EventCode=1) ("*rclone.exe*" OR "*curl.exe*")
) OR ( 
  (EventCode=4688 OR EventCode=1) ("*vssadmin*" AND "*delete shadows*")
)
| transaction host maxspan=60m
| search ("*7z.exe*" OR "*WinRAR.exe*") AND ("*rclone.exe*" OR "*curl.exe*") AND "*vssadmin*" AND "*delete shadows*"
| eval Attack_Chain = "CRITICAL ATTACK: Data Compression -> Internet Exfiltration -> Shadow Copies Destruction"
| table _time, host, duration, Attack_Chain
```

### Triage & Recommended Actions

This is a Crisis scenario (P1 Incident). The exfiltration and destruction of backups indicate that the ransomware is one step away from encrypting the entire disk.

1. **Immediate Isolation:** Physically or logically disconnect the machine from the network.

2. **IoC Search:** Identify which IP address or domain `curl.exe` or `rclone.exe` were communicating with to block it at the perimeter firewall level.

3. **Damage Control:** Check network logs to verify how many Mega/Gigabytes of data were exfiltrated.
