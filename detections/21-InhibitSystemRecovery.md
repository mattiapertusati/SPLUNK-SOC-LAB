# 🚨 Detection Rule: Inhibit System Recovery (Volume Shadow Copy Deletion)

## 📋 Obiettivo
Rilevare l'eliminazione delle copie di backup (Volume Shadow Copies) del sistema operativo. Questa è un'azione classificata come altamente sospetta, in quanto viene eseguita quasi sistematicamente dai Ransomware nelle prime fasi dell'infezione per impedire alla vittima di ripristinare i file originali dopo la cifratura.

## 🎯 MITRE ATT&CK Mapping
* **Tactic:** Impact (TA0040)
* **Technique:** Inhibit System Recovery (T1490)

## 🚦 Alert Metadata
* **Severity:** CRITICAL
* **Confidence:** High
* **False Positives:** Attività di manutenzione straordinaria dei dischi da parte di amministratori di sistema legittimi.

---

## 🟢 Splunk Query (SPL)
*Ricerca che copre non solo vssadmin, ma anche wmic e wbadmin, strumenti alternativi noti per ottenere lo stesso risultato malevolo.*

```splunk
index=wineventlog EventCode=4688 earliest=-24h (NewProcessName="*\\vssadmin.exe" OR NewProcessName="*\\wmic.exe" OR NewProcessName="*\\wbadmin.exe") CommandLine="*delete*" CommandLine="*shadow*"
| table _time, host, User, NewProcessName, CommandLine
```

## 🔵 Microsoft Sentinel Query (KQL)

```kql
SecurityEvent
| where EventID == 4688 and TimeGenerated > ago(24h)
| where NewProcessName endswith "vssadmin.exe" or NewProcessName endswith "wmic.exe" or NewProcessName endswith "wbadmin.exe"
| where CommandLine contains "delete" and CommandLine contains "shadow"
| project TimeGenerated, Computer, Account, NewProcessName, CommandLine
```

## 🟡 Sigma Rule (YAML)

```sigma
title: Inhibit System Recovery - Volume Shadow Copy Deletion
id: a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d
status: experimental
description: Rileva l'esecuzione di comandi per eliminare le copie shadow del volume, un comportamento tipico dei ransomware.
author: Mattia
date: 2026/07/14
tags:
    - attack.impact
    - attack.t1490
logsource:
    category: process_creation
    product: windows
detection:
    selection_process:
        Image|endswith:
            - '\vssadmin.exe'
            - '\wmic.exe'
            - '\wbadmin.exe'
    selection_cli:
        CommandLine|contains|all:
            - 'delete'
            - 'shadow'
    condition: selection_process and selection_cli
falsepositives:
    - Task programmati di pulizia disco o amministratori di sistema (richiede investigazione immediata).
level: critical
```
