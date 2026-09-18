# Multi-Stage Attack: Lateral Movement & Persistence

### Description
This **Advanced Correlation** rule tracks a typical post-compromise maneuver. The alert triggers if, within 45 minutes on the same machine, an attacker moves laterally by installing the PsExec service, creates a scheduled task to ensure persistence upon reboot, and alters the Windows firewall rules to facilitate Command and Control (C2) communications.

## MITRE ATT&CK
* **Tactic:** Lateral Movement (TA0008), Persistence (TA0003), Defense Evasion (TA0005)
* **Technique:** SMB/Windows Admin Shares (T1021.002), Scheduled Task (T1053.005), Impair Defenses: Disable or Modify System Firewall (T1562.004)

## Alert Metadata
* **Severity:** CRITICAL
* **Confidence:** High
* **Impact:** Critical

### SPL Query (Correlation Engine)
```splunk
(index=wineventlog OR index=sysmon) 
( 
  EventCode=7045 "*PSEXESVC*" 
) OR ( 
  EventCode=4698 
) OR ( 
  EventCode=4688 "*netsh*" "*firewall*"
)
| transaction host maxspan=45m
| search "*PSEXESVC*" AND EventCode=4698 AND "*netsh*"
| eval Attack_Chain="CRITICAL ALERT: Lateral Movement Execution -> Persistence via Scheduled Task -> Firewall Modification"
| table _time, host, duration, Attack_Chain
```

### Triage & Recommended Actions

This is a strong indicator that the attacker has already bypassed perimeter defenses and is spreading through the network.

1. **Containment:** Isolate the infected host immediately to block further lateral movements.

2. **Reverse Tracking:** Identify which IP address initiated the PsExec connection to find "Patient Zero" (the host from which the attacker jumped).

3. **Remediation:** Remove the unusual scheduled task and restore the original firewall policies.
