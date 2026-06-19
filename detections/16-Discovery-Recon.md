# 🚨 Detection Rule: Local & Domain Reconnaissance (Discovery)

## 📋 Obiettivo
Identificare attività di ricognizione (Situational Awareness) condotta da un attaccante che ha appena ottenuto l'accesso iniziale a un endpoint. L'attaccante utilizza binari nativi del sistema operativo (Living off the Land) per mappare l'utente corrente, la configurazione di rete, i processi attivi e l'architettura del dominio.

## 🎯 MITRE ATT&CK Mapping
* **Tactic:** Discovery (TA0007)
* **Technique:** 
  * System Owner/User Discovery (T1033)
  * System Network Configuration Discovery (T1016)
  * Permission Groups Discovery: Domain Groups (T1069.002)
  * System Information Discovery (T1082)
  * System Network Connections Discovery (T1049)

## 🚦 Alert Metadata
* **Severity:** MEDIUM
* **Confidence:** Medium 
* **False Positives:** Script di logon/logoff aziendali, software di inventory management, amministratori IT che eseguono troubleshooting manuale.

---

## 🟢 Splunk Query (SPL)
*La query utilizza l'operatore IN per ottimizzare la ricerca e include filtri condizionali basati sulla relazione Parent-Child per ridurre i falsi positivi noti (es. agenti di monitoraggio legittimi).*

```splunk
index=sysmon EventCode=1
Image IN ("*\\whoami.exe", "*\\net.exe", "*\\systeminfo.exe", "*\\ipconfig.exe", "*\\nltest.exe", "*\\arp.exe", "*\\tasklist.exe", "*\\nbtstat.exe", "*\\qwinsta.exe") NOT (ParentImage="*\\agente_monitoraggio.exe" AND Image="*\\tasklist.exe") NOT (ParentImage="*\\agente_monitoraggio.exe" AND Image="*\\ipconfig.exe")
| eval User = mvindex(User, 1)
| table _time, host, User, CommandLine, ParentImage, ParentCommandLine
```
## 🔵 Microsoft Sentinel Query (KQL)

```kql
DeviceProcessEvents
| where FileName in~ ("whoami.exe", "net.exe", "systeminfo.exe", "ipconfig.exe", "nltest.exe", "arp.exe", "tasklist.exe", "nbtstat.exe", "qwinsta.exe")
| where not(InitiatingProcessFileName =~ "agente_monitoraggio.exe" and FileName=~ "tasklist.exe")
| where not(InitiatingProcessFileName =~ "agente_monitoraggio.exe" and FileName=~ "ipconfig.exe")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InititatingProcessCommandLine, InititatingProcessFileName
```
## 🟡 Sigma Rule (YAML)

```sigma
title: Rilevamento Comandi di Ricognizione ed Enumerazione (Discovery)
id:  7d6200b6-dc10-4aa4-b0d6-814b326796f8
status: experimental
description: Rileva l'esecuzione di tool nativi di Windows utilizzati per la ricognizione del sistema, filtrando i processi padre legittimi.
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
    - Script di inventario IT legittimi
    - Agenti di monitoraggio aziendali
level: high

```


