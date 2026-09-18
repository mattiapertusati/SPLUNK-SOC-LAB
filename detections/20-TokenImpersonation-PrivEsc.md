# Detection Rule: Access Token Manipulation (Impersonation)

## Objective
Detect the assignment of special privileges (Special Logon) to non-standard accounts. A Token Impersonation attack occurs when an attacker steals or duplicates the security token of another process with elevated privileges, allowing them to perform actions on behalf of that user without needing to know their credentials.

The privileges most commonly abused and monitored in this rule are:
* **SeImpersonatePrivilege:** Allows a program to temporarily impersonate a user.
* **SeAssignPrimaryTokenPrivilege:** Allows the assignment of access tokens to a new process (often used in combination with SeImpersonate).
* **SeDebugPrivilege:** Allows the inspection of memory from other processes (abused by tools like Mimikatz to read passwords inside LSASS).
* **SeTcbPrivilege:** The highest privilege (Trusted Computer Base), which allows a process to act as part of the operating system core.

*Note: To generate this telemetry in a laboratory environment, advanced Windows auditing must be enabled using the command: `auditpol /set /subcategory:"Special Logon" /success:enable`.*

## MITRE ATT&CK Mapping
* **Tactic:** Privilege Escalation (TA0004), Defense Evasion (TA0005)
* **Technique:** Access Token Manipulation: Token Impersonation/Theft (T1134.001)

## Alert Metadata
* **Severity:** HIGH
* **Confidence:** Medium
* **False Positives:** Corporate backup services, legitimate system monitoring software, or administrative service accounts.

---

## Splunk Query (SPL)
*Optimized search by filtering out machine and SYSTEM accounts directly in the base query, and then isolating critical privileges.*

```splunk
index=wineventlog EventCode=4672 earliest=-24h NOT (SubjectUserName="SYSTEM" OR SubjectUserName="*\$") (PrivilegeList="*SeDebugPrivilege*" OR PrivilegeList="*SeTcbPrivilege*" OR PrivilegeList="*SeImpersonatePrivilege*" OR PrivilegeList="*SeAssignPrimaryTokenPrivilege*")
| table _time, host, SubjectUserName, PrivilegeList
```

## Microsoft Sentinel Query (KQL)
*Optimized syntax using the has operator to search within the privilege string, excluding system accounts.*

```kql
SecurityEvent
| where EventID == 4672 and TimeGenerated > ago(24h)
| where SubjectUserName != "SYSTEM" and SubjectUserName !endswith "\$"
| where (PrivilegeList has "SeImpersonatePrivilege" or PrivilegeList has "SeAssignPrimaryTokenPrivilege" or PrivilegeList has "SeDebugPrivilege" or PrivilegeList has "SeTcbPrivilege")
| project TimeGenerated, Computer, SubjectUserName, PrivilegeList
```

## Sigma Rule (YAML)

```sigma
title: Detection of Token Impersonation - Special Privileges
id: 4a2b3c4d-e5f6-7a8b-9c0d-1e2f3a4b5c6d
status: experimental
description: Detects the assignment of special privileges (SeImpersonate, SeDebug, etc.) to non-standard users to identify Token Impersonation attempts.
author: Mattia
date: 2026/07/13
references:
    - [https://mitre.org](https://mitre.org)
tags:
    - attack.privilege_escalation
    - attack.defense_evasion
    - attack.t1134.001
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4672
        PrivilegeList|contains:
            - 'SeImpersonatePrivilege'
            - 'SeAssignPrimaryTokenPrivilege'
            - 'SeDebugPrivilege'
            - 'SeTcbPrivilege'
    filter_system:
        SubjectUserName: 'SYSTEM'
    filter_machine:
        SubjectUserName|endswith: '\$'
    condition: selection and not 1 of filter_*
falsepositives:
    - System backup and recovery software.
    - Domain administrators performing advanced maintenance tasks.
level: high
```
