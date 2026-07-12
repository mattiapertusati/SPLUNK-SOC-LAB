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

## SOP-SEC-042: Incident Response Playbook – Rilevamento Attività WMI / Esecuzione Sospetta

Segui questa guida nello specifico caso di Rilevamento Attività WMI / Esecuzione Sospetta e possibile lateral movement

**Fase 1 - Triage e Qualificazione**

L'obiettivo di questa fase è capire se l'attività segnalata sia effettivamente malevola oppure riconducibile ad una manutenzione ordinaria (False Positive)

- Analisi della CommandLine: Esaminare l'intera stringa di comando del log per trovare dettagli utili alla nostra ricerca, elementi come l'uso di encoding, offuscamento, download esterni ecc
- Verifica delle linee guida di Amministrazione: Verificare se il processo che ha generato l'attività fa parte delle task di automazione legittime.
- Check con altri Team: Se l'attività proviene da un account noto, chiedere direttamente al Team convolto informazioni su apertura di **ticket** per manutenzione o altro

**Fase 2 - Identificare la sorgente**

WMI viene spesso usata per attacchi laterali guidati da remoto. E' necessario identificare il cuore di tale attacco.

- Verificare se sono avvenuti login esterni da remoto (Type 3) nell'intervallo simile a quello del log.
- Cercare l'IP sorgente è la sua presenza nella mappa della rete, per comprenderne percorso e possibile punto d'ingresso/uscita.

**Fase 3 - Analisi dell'impatto**

Dobbiamo determinare le azione eseguite dall'attaccante sul target

- Monitorare l'intero albero del programma, come sottoprocessi, servizi o qualsiasi altro collegamento utile all'attaccante. Ogni singola opzione può essere quella decisiva.
- Verificare se sono avvenute creazioni di account o processi nuovi, modifiche alle chiavi di registro o alla schedulazione di task

**Fase 4 - Isolamento degli Indicatori**

Definire il perimetro dell'attacco all'interno dell'infrastruttura aziendale, cosi da capire in che zona operare.

- Estrazione degli IoC, ovvero le tracce lasciate dall'hacker durante l'esecuzione dell'attacco. Ogni traccia deve essere isolata, come hash dei file, indirizzi IP esterni C2, domini malevoli o stringhe di comando codificate.
- Verificare la presenza di IoC simili magari anche su dispositivi che fanno parte dello stesso gruppo o team, per verificare se è avvenuto o meno un spostamento laterale.

**Fase 5 - Contenimento ed Escalation**

Questa ultima fase mira a mitigare la minaccia prima che si espanda in modo irreversibile.

- Contenere l'host tramite EDR/XDR isolandolo dalla rete aziendale, cosi da bloccare la comunicazione verso l'esterno. Togliamo le mani e gli occhi dell'hacker.
- Contenere anche l'identità, ovvero, bloccare gli account compromessi coinvolti nell'attacco
- Includere gli IoC trovati nella documentazione di escalation in precedenza, la timeline degli eventi e l'impatto di ognuno ed effettuare un escalation al Team Incident Response **L2** specificando tutte le informazioni accumulate come, possibile lateral movement, host target isolato, account compromessi ecc.
