# Detection Rule: Lateral Movement & Execution via WMI

## Objective
Detect the execution of processes generated via Windows Management Instrumentation (WMI). Attackers often abuse the WMI service (`WmiPrvSE.exe`) to execute remote commands (Lateral Movement) or for local execution purposes (Execution), bypassing traditional defenses. The rule excludes legitimate system processes by verifying absolute paths.

## MITRE ATT&CK Mapping
* **Tactic:** Execution (TA0002), Lateral Movement (TA0008)
* **Technique:** Windows Management Instrumentation (T1047)

## Alert Metadata
* **Severity:** HIGH
* **Confidence:** Medium
* **False Positives:** Corporate inventory management software, legitimate IT administration scripts using WMI for maintenance tasks.

---

## Splunk Query (SPL)
*Optimization: Use of `like` to force full-path validation, preventing evasions based on file renaming, and inclusion of the `TokenElevationType` to contextualize child process privileges.*

```splunk
index=wineventlog EventCode=4688
| where like(ParentProcessName, "%\\Windows\\System32\\wbem\\WmiPrvSE.exe")
| where NOT (like(NewProcessName, "%\\System32\\svchost.exe") OR like(NewProcessName, "%\\Program Files\\Windows Defender\\MsMpEng.exe"))
| table _time, host, User, CommandLine, ParentProcessName, TokenElevationType
```

## Microsoft Sentinel Query (KQL)

```kql
SecurityEvent
| where EventID == 4688
| where ParentProcessName endswith @"\Windows\System32\wbem\WmiPrvSE.exe"
| where NewProcessName !endswith @"\System32\svchost.exe" and NewProcessName !endswith @"\Program Files\Windows Defender\MsMpEng.exe"
| project TimeGenerated, Computer, Account, CommandLine, ParentProcessName, TokenElevationType
```

## Sigma Rule (YAML)

```sigma
title: Suspicious Process Creation via WMI
id: 6099d595-71c5-4095-b544-7868e7519921
status: experimental
description: Identifies the creation of unusual processes started by the WMI service, excluding legitimate system activity.
author: Mattia
date: 2026/07/09
tags:
    - attack.execution
    - attack.lateral_movement
    - attack.t1047
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4688
        ParentProcessName|endswith: '\Windows\System32\wbem\WmiPrvSE.exe'
    filter_legitimate:
        NewProcessName|endswith:
            - '\System32\svchost.exe'
            - '\Program Files\Windows Defender\MsMpEng.exe'
    condition: selection and not filter_legitimate
fields:
    - Computer
    - User
    - CommandLine
    - ParentProcessName
    - TokenElevationType
falsepositives:
    - Legitimate administrative activity via WMI
level: medium
```

## SOP-SEC-042: Incident Response Playbook – WMI Activity / Suspicious Execution Detection

Follow this guide specifically for WMI Activity / Suspicious Execution Detection and possible lateral movement.

**Phase 1 - Triage and Qualification**

The objective of this phase is to understand if the reported activity is actually malicious or if it can be traced back to ordinary maintenance (False Positive).

- CommandLine Analysis: Examine the entire command string of the log to find useful details for our research, elements such as the use of encoding, obfuscation, external downloads, etc.
- Administration Guidelines Verification: Verify if the process that generated the activity is part of legitimate automation tasks.
- Check with other Teams: If the activity comes from a known account, directly ask the involved Team for information regarding an open maintenance ticket or other reasons.

**Phase 2 - Identify the Source**

WMI is often used for remote lateral attacks. It is necessary to identify the core of this attack.

- Verify if external remote logins (Type 3) occurred within a similar timeframe as the log.
- Search for the source IP address and its presence on the network map to understand its path and possible entry/exit point.

**Phase 3 - Impact Analysis**

We must determine the actions executed by the attacker on the target.

- Monitor the entire program tree, such as subprocesses, services, or any other useful connection to the attacker. Every single option can be the decisive one.
- Verify if any user account creations, new processes, registry key modifications, or task scheduling have occurred.

**Phase 4 - Indicator Isolation**

Define the perimeter of the attack within the corporate infrastructure to understand which zone to operate in.

- IoC Extraction, meaning the traces left by the hacker during the execution of the attack. Every trace must be isolated, such as file hashes, external C2 IP addresses, malicious domains, or encoded command strings.
- Verify the presence of similar IoCs on devices belonging to the same group or team to check whether lateral movement has occurred.

**Phase 5 - Containment and Escalation**

This final phase aims to mitigate the threat before it expands irreversibly.

- Contain the host via EDR/XDR by isolating it from the corporate network to block communication with the outside. We remove the hacker's hands and eyes.
- Contain the identity as well, meaning block the compromised accounts involved in the attack.
- Include the found IoCs in the previously created escalation documentation, along with the event timeline and the impact of each. Escalate to the Incident Response L2 Team, specifying all accumulated information such as possible lateral movement, isolated target host, compromised accounts, etc.
