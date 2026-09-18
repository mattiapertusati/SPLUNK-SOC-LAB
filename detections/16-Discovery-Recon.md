# Detection Rule: Local & Domain Reconnaissance (Discovery)

## Objective
Identify reconnaissance activities (Situational Awareness) carried out by an attacker who has just gained initial access to an endpoint. The attacker uses native operating system binaries (Living off the Land) to map the current user, network configuration, active processes, and domain architecture.

## MITRE ATT&CK Mapping
* **Tactic:** Discovery (TA0007)
* **Technique:** 
  * System Owner/User Discovery (T1033)
  * System Network Configuration Discovery (T1016)
  * Permission Groups Discovery: Domain Groups (T1069.002)
  * System Information Discovery (T1082)
  * System Network Connections Discovery (T1049)

## Alert Metadata
* **Severity:** MEDIUM
* **Confidence:** Medium 
* **False Positives:** Corporate logon/logoff scripts, inventory management software, IT administrators performing manual troubleshooting.

---

## Splunk Query (SPL)
*The query uses the IN operator to optimize the search and includes conditional filters based on the Parent-Child relationship to reduce known false positives (such as legitimate monitoring agents).*

```splunk
index=sysmon EventCode=1
Image IN ("*\\whoami.exe", "*\\net.exe", "*\\systeminfo.exe", "*\\ipconfig.exe", "*\\nltest.exe", "*\\arp.exe", "*\\tasklist.exe", "*\\nbtstat.exe", "*\\qwinsta.exe") NOT (ParentImage="*\\agente_monitoraggio.exe" AND Image="*\\tasklist.exe") NOT (ParentImage="*\\agente_monitoraggio.exe" AND Image="*\\ipconfig.exe")
| eval User = mvindex(User, 1)
| table _time, host, User, CommandLine, ParentImage, ParentCommandLine
```
## Microsoft Sentinel Query (KQL)

```kql
DeviceProcessEvents
| where FileName in~ ("whoami.exe", "net.exe", "systeminfo.exe", "ipconfig.exe", "nltest.exe", "arp.exe", "tasklist.exe", "nbtstat.exe", "qwinsta.exe")
| where not(InitiatingProcessFileName =~ "agente_monitoraggio.exe" and FileName =~ "tasklist.exe")
| where not(InitiatingProcessFileName =~ "agente_monitoraggio.exe" and FileName Pis~ "ipconfig.exe")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessFileName
```
## Sigma Rule (YAML)

```sigma
title: Detection of Reconnaissance and Enumeration Commands (Discovery)
id:  7d6200b6-dc10-4aa4-b0d6-814b326796f8
status: experimental
description: Detects the execution of native Windows tools used for system reconnaissance, filtering out legitimate parent processes.
references:
    - https://mitre.org
author: Mattia
date: 2026/06/19
tags:
    - attack.discovery
    - attack.t1033 # ex: whoami
    - attack.t1087 # ex: net user
    - attack.t1016
    - attack.t1069.002
    - attack.t1049
    - attack.t1082
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\whoami.exe'
            - '\net.exe'
            - '\net1.exe'
            - '\systeminfo.exe'
            - '\ipconfig.exe'
            - '\nltest.exe'
            - '\arp.exe'
            - '\tasklist.exe'
            - '\nbtstat.exe'
            - '\qwinsta.exe'
    filter_agente:
        ParentImage|endswith: '\agente_monitoraggio.exe'
        Image|endswith:
            - '\tasklist.exe'
            - '\ipconfig.exe'  
    condition: selection and not filter_agente
falsepositives:
    - Legitimate IT inventory scripts
    - Corporate monitoring agents
level: high
```
