# 🚨 Detection Rule: Rundll32 Proxy Execution

## 📋 Obiettivo
Rilevare l'abuso del binario legittimo di Windows `rundll32.exe` per l'esecuzione di codice malevolo (Proxy Execution). Gli attaccanti utilizzano spesso Rundll32 per caricare DLL malevole mascherandole dietro un processo di sistema affidabile, aggirando così i controlli preventivi (es. AppLocker). Questa regola identifica l'esecuzione di Rundll32 da percorsi directory sospetti (dropper locations) escludendo i processi genitori di sistema noti.

## 🎯 MITRE ATT&CK Mapping
* **Tactic:** Defense Evasion (TA0005)
* **Technique:** System Binary Proxy Execution: Rundll32 (T1218.011)

## 🚦 Alert Metadata
* **Severity:** HIGH
* **Confidence:** Medium
* **False Positives:** Installatori di software di terze parti o vecchie applicazioni legacy che utilizzano Rundll32 in modo non standard da percorsi temporanei.

---

## 🟢 Splunk Query (SPL)
*Filtro sulle directory tipicamente usate dai malware per droppare i payload (Users, Temp, ProgramData), escludendo i parent process legittimi come explorer, svchost e msiexec.*

```splunk
index=sysmon EventCode=1 earliest=-24h Image="*\\rundll32.exe" NOT (ParentImage="*\\svchost.exe" OR ParentImage="*\\msiexec.exe" OR ParentImage="*\\explorer.exe") (CommandLine="*\\Users\\*" OR CommandLine="*\\Temp\\*" OR CommandLine="*\\ProgramData\\*")
| table _time, host, User, CommandLine, ParentImage, ParentCommandLine
```

## 🔵 Microsoft Sentinel Query (KQL)

```kql
DeviceProcessEvents
| where TimeGenerated >= ago(24h)
| where FileName =~ "rundll32.exe"
| where InitiatingProcessFileName !endswith @"\svchost.exe" 
    and InitiatingProcessFileName !endswith @"\msiexec.exe" 
    and InitiatingProcessFileName !endswith @"\explorer.exe"
| where ProcessCommandLine contains @"\Users\" 
     or ProcessCommandLine contains @"\Temp\" 
     or ProcessCommandLine contains @"\ProgramData\"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

## 🟡 Sigma Rule (YAML)

```sigma
title: Rilevamento Esecuzioni Anomale di Rundll32
id: 550e8400-e29b-41d4-a716-446655440000
status: experimental
description: Identifica l'esecuzione di rundll32.exe da percorsi insoliti o con genitori sospetti (possibile esecuzione di DLL malevole o dropper).
author: Mattia
date: 2026/07/20
tags:
    - attack.defense_evasion
    - attack.t1218.011
logsource:
    category: process_creation
    product: windows
detection:
    selection_image:
        Image|endswith: '\rundll32.exe'
    filter_parent:
        ParentImage|endswith:
            - '\svchost.exe'
            - '\msiexec.exe'
            - '\explorer.exe'
    selection_commandline:
        CommandLine|contains:
            - '\Users\'
            - '\Temp\'
            - '\ProgramData\'
    condition: selection_image and selection_commandline and not filter_parent
fields:
    - Computer
    - User
    - CommandLine
    - ParentImage
    - ParentCommandLine
falsepositives:
    - Attività amministrative legittime o installazioni software.
level: medium
```
