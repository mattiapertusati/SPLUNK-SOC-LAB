# Detection Rule: Linux SUID Discovery & Privilege Escalation

## Objective
Detect an attacker's activity on a Linux system aimed at privilege escalation using the SUID bit. The rule intercepts three distinct stages of this attack chain:
1. Verification of current permissions (`sudo -l`).
2. Search for pre-existing exploitable SUID files (`find / -perm -4000`).
3. Creation or modification of a file to assign it the SUID bit via symbolic or octal mode (`chmod +s` / `chmod 4755`).

## MITRE ATT&CK Mapping
* **Tactic:** Discovery (TA0007), Privilege Escalation (TA0004)
* **Technique:** * File and Directory Discovery (T1083)
  * Abuse Elevation Control Mechanism: Setuid and Setgid (T1548.001)

## Alert Metadata
* **Severity:** HIGH
* **Confidence:** High
* **Validation Status:** Validated in Lab
* **False Positives:** Legitimate deployment scripts that assign specific privileges or system administrators performing extraordinary maintenance.

---

## Splunk Query (SPL)
*Search using nested logical operators to intercept the three attack vectors, with an exclusion filter for known scripts placed outside the main block to optimize performance.*

```splunk
index=linux_logs
| where (like(CommandLine, "%sudo%") AND like(CommandLine, "%-l%"))
     OR (like(CommandLine, "%find%") AND like(CommandLine, "%-perm%") AND like(CommandLine, "%-4000%"))
     OR (like(CommandLine, "%chmod%") AND (like(CommandLine, "%+s%") OR match(CommandLine, "\\b[4-7][0-7]{3}\\b")))
| where NOT like(CommandLine, "%/opt/scripts/deploy.sh%")
| table _time, host, User, CommandLine

```

---

## Microsoft Sentinel Query (KQL)

```kql
DeviceProcessEvents
| where (ProcessCommandLine contains "sudo" and ProcessCommandLine contains "-l") or
        (ProcessCommandLine contains "find" and ProcessCommandLine contains "-perm" and ProcessCommandLine contains "-4000") or 
        (ProcessCommandLine contains "chmod" and (ProcessCommandLine contains "+s" or ProcessCommandLine matches regex @"\b[4-7][0-7]{3}\b"))
| where ProcessCommandLine !contains "/opt/scripts/deploy.sh"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
```

## Sigma Rule (YAML)

```sigma
title: Linux SUID Discovery and Privilege Escalation
id: 8c1b92a3-f570-4d56-a9bb-12a83bd78e51
status: experimental # Pending Linux Endpoint validation
description: Detects commands used to discover or create SUID files, using strict regex on octal permissions.
references:
    - [https://mitre.org](https://mitre.org)
author: Mattia
date: 2026/06/29
tags:
    - attack.discovery
    - attack.privilege_escalation
    - attack.t1083
    - attack.t1548.001
logsource:
    category: process_creation
    product: linux
detection:
    selection_sudo:
        CommandLine|contains|all:
            - 'sudo'
            - '-l'
    selection_find:
        CommandLine|contains|all:
            - 'find'
            - '-perm'
            - '-4000'
    selection_chmod:
        CommandLine|contains: 'chmod'
    selection_chmod_suid:
        - CommandLine|contains: '+s'
        - CommandLine|re: '\b[4-7][0-7]{3}\b'
    filter_deploy:
        CommandLine|contains: '/opt/scripts/deploy.sh'
    condition: (selection_sudo or selection_find or (selection_chmod and selection_chmod_suid)) and not filter_deploy
falsepositives:
    - System administrators during troubleshooting sessions.
level: high
```

The detection has been validated in the controlled laboratory environment. See `validation/18-Linux-SUID-PrivEsc-Validation.md` for validation evidence.
