# 🚨 Detection Rule: Lateral Movement & Execution via WMI

## 📋 Obiettivo
Rilevare l'esecuzione di processi generati tramite Windows Management Instrumentation (WMI). Gli attaccanti abusano spesso del servizio WMI (`WmiPrvSE.exe`) per eseguire comandi da remoto (Lateral Movement) o per scopi di esecuzione locale (Execution), bypassando le difese tradizionali. La regola esclude i processi di sistema legittimi verificando i percorsi assoluti.

## 🎯 MITRE ATT&CK Mapping
* **Tactic:** Execution (TA0002), Lateral Movement (TA0008)
* **Technique:** Windows Management Instrumentation (T1047)

## 🚦 Alert Metadata
* **Severity:** HIGH
* **Confidence:** Medium
* **False Positives:** Software di inventory management aziendale, script di amministrazione IT legittimi che usano WMI per task di manutenzione.

---

## 🟢 Splunk Query (SPL)
*Ottimizzazione: Uso di `like` per forzare la validazione dell'intero percorso, prevenendo evasioni basate su rinominazione di file, e inclusione del `TokenElevationType` per contestualizzare i privilegi del processo figlio.*

```splunk
index=wineventlog EventCode=4688
| where like(ParentProcessName, "%\\Windows\\System32\\wbem\\WmiPrvSE.exe")
| where NOT (like(NewProcessName, "%\\System32\\svchost.exe") OR like(NewProcessName, "%\\Program Files\\Windows Defender\\MsMpEng.exe"))
| table _time, host, User, CommandLine, ParentProcessName, TokenElevationType
```

## 🔵 Microsoft Sentinel Query (KQL)

```kql
SecurityEvent
| where EventID == 4688
| where ParentProcessName endswith @"\Windows\System32\wbem\WmiPrvSE.exe"
| where NewProcessName !endswith @"\System32\svchost.exe" and NewProcessName !endswith @"\Program Files\Windows Defender\MsMpEng.exe"
| project TimeGenerated, Computer, Account, CommandLine, ParentProcessName, TokenElevationType
```

## 🟡 Sigma Rule (YAML)

```sigma
title: Rilevamento di Processi Sospetti Generati da WMI
id: 6099d595-71c5-4095-b544-7868e7519921
status: experimental
description: Identifica la creazione di processi insoliti avviati dal servizio WMI escludendo l'attività legittima di sistema.
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
    - Attività amministrativa legittima tramite WMI
level: medium
```
