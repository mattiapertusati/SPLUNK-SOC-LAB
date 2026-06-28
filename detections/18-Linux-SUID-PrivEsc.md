# 🚨 Detection Rule: Linux SUID Discovery & Privilege Escalation

## 📋 Obiettivo
Rilevare l'attività di un attaccante su un sistema Linux mirata all'escalation dei privilegi tramite il bit SUID. La regola intercetta tre fasi distinte di questa catena di attacco:
1. Verifica dei permessi correnti (`sudo -l`).
2. Ricerca di file SUID preesistenti sfruttabili (`find / -perm -4000`).
3. Creazione o modifica di un file per assegnargli il bit SUID tramite modalità simbolica o ottale (`chmod +s` / `chmod 4755`).

## 🎯 MITRE ATT&CK Mapping
* **Tactic:** Discovery (TA0007), Privilege Escalation (TA0004)
* **Technique:** * File and Directory Discovery (T1083)
  * System Information Discovery (T1082)
  * Abuse Elevation Control Mechanism: Setuid and Setgid (T1548.001)

## 🚦 Alert Metadata
* **Severity:** HIGH
* **Confidence:** High
* **False Positives:** Script di deployment legittimi che assegnano privilegi specifici o amministratori di sistema che eseguono manutenzione straordinaria.

---

## 🟢 Splunk Query (SPL)
*Ricerca tramite operatori logici annidati per intercettare i tre vettori di attacco, con filtro di esclusione per script noti.*

```splunk
index=linux_logs EventCode=1
(
  (CommandLine="*sudo*" AND CommandLine="*-l*") OR 
  (CommandLine="*find*" AND CommandLine="*-perm*" AND CommandLine="*-4000*") OR 
  (CommandLine="*chmod*" AND (CommandLine="*+s*" OR CommandLine="*47*"))
)
NOT CommandLine="*/opt/scripts/deploy.sh*"
| table _time, host, User, CommandLine
```

## 🔵 Microsoft Sentinel Query (KQL)

```kql
DeviceProcessEvents
| where (ProcessCommandLine contains "sudo" and ProcessCommandLine contains "-l") or
        (ProcessCommandLine contains "find" and ProcessCommandLine contains "-perm" and ProcessCommandLine contains "-4000") or 
        (ProcessCommandLine contains "chmod" and (ProcessCommandLine contains "+s" or ProcessCommandLine contains "47"))
| where ProcessCommandLine !contains "/opt/scripts/deploy.sh"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
```

## 🟡 Sigma Rule (YAML)

```sigma
title: Linux SUID Discovery and Privilege Escalation
id: 8c1b92a3-f570-4d56-a9bb-12a83bd78e51
status: experimental
description: Rileva l'esecuzione di comandi utilizzati per scoprire file SUID esistenti o per assegnare il bit SUID a nuovi file, filtrando path di deployment noti.
references:
    - [https://mitre.org](https://mitre.org)
author: Mattia
date: 2026/06/28
tags:
    - attack.discovery
    - attack.privilege_escalation
    - attack.t1083
    - attack.t1082
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
        CommandLine|contains:
            - '+s'
            - '47'
    filter_deploy:
        CommandLine|contains: '/opt/scripts/deploy.sh'
    condition: (selection_sudo or selection_find or (selection_chmod and selection_chmod_suid)) and not filter_deploy
falsepositives:
    - Amministratori di sistema durante sessioni di troubleshooting.
    - Script di provisioning pre-approvati (es. Ansible).
level: high
```
