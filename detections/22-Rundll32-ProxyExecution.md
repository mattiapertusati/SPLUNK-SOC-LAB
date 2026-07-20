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

---

## 📖 L1 Triage Playbook (Analyst Response Steps)

Quando si attiva questo alert, indica il potenziale abuso di un binario di sistema (Living off the Land) per nascondere l'esecuzione di codice malevolo o scaricare payload secondari. L'analista L1 deve seguire questi step:

### 1. Analisi della Catena di Esecuzione e del Payload (Triage Iniziale)
Analizzare i log del processo per ricostruire il contesto dell'esecuzione:
* **Verificare il `ParentImage`:** Determinare l'origine dell'attacco. Se il processo padre è un'applicazione di Office (es. `winword.exe`) o un browser, indica probabile Phishing o drive-by download.
* **Esaminare la `CommandLine`:** Identificare il percorso esatto della DLL caricata. Confermare se risiede in cartelle anomale per le librerie di sistema (es. `C:\Users\`, `C:\Temp\`, `C:\ProgramData\`).
* **Analisi OSINT:** Estrarre l'hash (SHA256) della DLL o analizzare il nome del file e verificarne la reputazione su piattaforme di threat intelligence (es. VirusTotal).

### 2. Analisi del Comportamento da Dropper (Network & File System)
Verificare se `rundll32.exe` sta agendo come downloader/dropper analizzando gli eventi successivi:
* **Eventi di Rete:** Controllare la telemetria EDR per rilevare connessioni in uscita sospette initiate da `rundll32.exe` verso IP o domini non noti (potenziale contatto con un server Command & Control).
* **Eventi sui File:** Ricercare eventi di creazione file (*DeviceFileEvents*), prestando attenzione a nuovi eseguibili o script rilasciati sul disco subito dopo la connessione di rete.

### 3. Contenimento e Isolamento (Host Isolation)
Se il comportamento malevolo è confermato (True Positive), procedere immediatamente con l'isolamento di rete logico dell'host tramite la console EDR. Questo impedirà al processo di contattare il server C2 o di effettuare movimenti laterali, mantenendo intatto il canale investigativo remoto. Accedere in Live Response e terminare l'albero dei processi coinvolti (genitore e figli).

### 4. Escalation a L2 con lista IOC e Report
Aprire un ticket di Incident Response per il livello L2 (Escalation) strutturato in questo modo:
* **Contesto e Azioni:** Segnalare l'host isolato, il processo infetto bloccato e confermare se l'attacco è derivato da un file Office/Email.
* **IOC per Threat Hunting:** Fornire i dati tecnici per la ricerca su larga scala, includendo: 
  * Indirizzi IP / Domini esterni contattati (C2).
  * Hash (SHA256) dei file droppati (DLL malevola, payload secondari).
  * La riga di comando esatta utilizzata per bypassare i controlli.
  * Il percorso dei file scritti sul disco.
