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

---

## 📖 L1 Triage Playbook (Analyst Response Steps)

Quando questo allarme si attiva sul SIEM, indicando un potenziale attacco Ransomware in corso (fase di distruzione dei backup locali), l'analista L1 deve eseguire immediatamente i seguenti step operativi:

### 1. Verifica attività del processo (Live Response)
Utilizzare la console Live Terminal dell'EDR per connettersi all'host compromesso. Verificare se il processo malevolo è ancora in esecuzione. Analizzare le metriche di sistema in tempo reale: un utilizzo prolungato e anomalo di CPU e Disco (100%) indica una probabile cifratura dei file in corso. Terminare (kill) immediatamente eventuali processi anomali o non riconosciuti.

### 2. Verifica di backup alternativi e offline
Interfacciarsi con il team IT o controllare le dashboard degli strumenti di backup aziendali (es. Veeam, server NAS isolati) per verificare l'esistenza di copie fisiche o immagini di sistema recenti e intatte. Controllare inoltre il versioning in Cloud (es. OneDrive/SharePoint) per i file utente. Prepararsi al ripristino, consapevoli della potenziale perdita del delta di dati generato dopo l'ultimo salvataggio utile.

### 3. Isolamento di rete del dispositivo
Procedere in parallelo con l'isolamento logico dell'host tramite la funzione "Isolate Host" della console EDR. Questo bloccherà ogni tipo di comunicazione di rete in entrata e in uscita (incluso l'accesso a share di rete condivise), impedendo il Lateral Movement del ransomware, ma manterrà attivo il canale cifrato di gestione dell'EDR per consentire al SOC di proseguire le indagini in sicurezza.

### 4. Escalation a L2 con lista IOC e Report
Aprire un ticket di Incident Response per il livello L2 (Escalation) includendo un riepilogo operativo e tecnico strutturato:
* **Contesto e Azioni (Summary):** Segnalare l'host isolato, lo stato delle metriche (CPU/Disco), eventuali processi terminati manualmente e il resoconto sui backup offline disponibili.
* **IOC per Threat Hunting:** Fornire i dati tecnici per la ricerca su larga scala, includendo: Hostname e IP della macchina infetta, account utente compromesso, timestamp esatto dell'evento, la riga di comando malevola rilevata e l'hash (SHA256) del processo che ha invocato l'eliminazione delle Shadow Copies.
