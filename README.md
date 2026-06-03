# 🛡️ End-to-End Splunk SIEM Engineering & Advanced Threat Hunting Lab

## 👤 Candidato: Mattia Pertusati
### 🎯 Progetto di Cyber Security, Incident Response & SOC Automation

---

## 📝 Descrizione del Progetto
Questo repository documenta la progettazione, la realizzazione e l'analisi forense avanzata di un laboratorio di **Security Operations Center (SOC)** basato sul framework aziendale **Detection Lab**. L'obiettivo del progetto è simulare una catena di attacco informatico completa (Kill Chain) contro un'infrastruttura Microsoft Active Directory e configurare un server **Splunk Enterprise** centrale per il monitoraggio, l'estrazione degli Indicatori di Compromissione (IoC) e l'automazione dei rilevamenti.

---

## 🗺️ Roadmap dello Sviluppo (Alberatura delle Fasi)

Il progetto è suddiviso in moduli strutturati, ognuno corredato da evidenze digitali, screenshot operativi e configurazioni tecniche:

*   **Fase 1: 📁 [01-Environment-Setup](./01-Environment-Setup)** ➔ Provisioning dell'infrastruttura multi-host via Vagrant e Oracle VirtualBox (`Logger`, `dc-prod`, `wef`, `win10-client`).
*   **Fase 2: 📁 [02-Sysmon-Installation](./02-Sysmon-Installation)** ➔ Implementazione di Microsoft Sysmon con template avanzato SwiftOnSecurity per l'eliminazione del rumore di fondo.
*   **Fase 3: 📁 [03-Log-Ingestion-Troubleshooting](./03-Log-Ingestion-Troubleshooting)** ➔ Protocollo analitico di troubleshooting forense applicato per la risoluzione del drop-out dei log.
*   **Fase 4: 📁 [04-Splunk-SPL-Fundamentals](./04-Splunk-SPL-Fundamentals)** ➔ Sviluppo di query analitiche in linguaggio SPL (`table`, `stats count by`, `where`) per la strutturazione dei dati.
*   **Fase 5: 📁 [05-Threat-Hunting-Base](./05-Threat-Hunting-Base)** ➔ Attività di triage su attacchi reali di Password Spraying e tracciamento delle attività di Discovery.
*   **Fase 6: 📁 [06-CyberChef-Analysis](./06-CyberChef-Analysis)** ➔ Reverse engineering e decodifica forense di payload PowerShell cifrati in Base64 (Reverse Shell).
*   **Fase 7: 📁 [07-Persistence-Detection](./07-Persistence-Detection)** ➔ Rilevamento di tecniche di persistenza e camuffamento (Masquerading) via `schtasks.exe` e `sc.exe`.
*   **Fase 8: 📁 [08-Credential-Theft-Forensics](./08-Credential-Theft-Forensics)** ➔ Monitoraggio del furto definitivo di credenziali tramite LSASS Process Dump e manipolazione di Mimikatz.
*   **Fase 9: 📁 [09-SOC-Automation](./09-SOC-Automation)** ➔ Ingegneria dei rilevamenti e attivazione di un Allarme in tempo reale (Real-time Alert) con logica di Throttling.

---

## 📐 Architettura di Rete del Laboratorio

La Sandbox utilizza una subnet privata in modalità Host-Only (`192.168.56.0/24`) isolata da Internet per garantire la sicurezza dell'host reale durante l'esecuzione dei payload:


| Nome Host | Indirizzo IP | Sistema Operativo | Ruolo e Servizi Core |
| :--- | :--- | :--- | :--- |
| **`logger`** | `192.168.56.105` | Ubuntu Linux 20.04 | Server SIEM centrale (Splunk Enterprise) |
| **`dc-prod`** | `192.168.56.102` | Windows Server 2016 | Domain Controller centrale (Active Directory / DNS) |
| **`wef`** | `192.168.56.103` | Windows Server 2016 | Windows Event Collector (Concentratore di log) |
| **`win10-client`** | `192.168.56.104` | Windows 10 Enterprise | Endpoint della vittima (Postazione client aziendale) |

---

## 🛠️ Nota Ingegneristica sul Troubleshooting dell'Ingestion Dati

Durante la **Fase 3**, i test di connettività di rete eseguiti dall'endpoint verso l'indexer centrale hanno confermato il corretto instradamento dei pacchetti sulla porta predefinita (`TcpTestSucceeded : True` sulla porta `9997` con un volume di traffico di **346 Eventi al Secondo (EPS)** certificato dai log di diagnostica `_internal`). 

Tuttavia, a causa di restrizioni rigide nei permessi di scrittura dei ruoli locali di Splunk Enterprise legati alla build automatica e alla mancanza dei descrittori nativi dei Source Type di Windows sul server Linux in background, la telemetria cruda subiva un drop-out visivo all'interno della dashboard principale.

**Soluzione Strategica Applicata (Pivot)**: Per convalidare gli obiettivi didattici e analitici ed evitare lo stallo dell'infrastruttura, il Threat Hunting è stato condotto importando con successo nell'indice `main` un dataset professionale strutturato in formato **JSON Lines (.jsonl)**, simulando una catena di attacco completa (Advanced Persistent Threat). Questo approccio metodologico ha permesso di dimostrare la piena padronanza del linguaggio SPL, delle metriche di tracciamento di Sysmon e della logica di contenimento degli incidenti, garantendo la perfetta riuscita del laboratorio.

---

## 🚀 Competenze Tecniche Dimostrate nel Portfolio
- **SIEM Engineering**: Installazione agenti, gestione indici, configurazione regole di Throttling e Suppression degli allarmi.
- **Threat Hunting & Incident Response**: Ricostruzione cronologica degli attacchi, analisi degli EventID di Windows e Sysmon.
- **Analisi Forense degli Artefatti**: Rilevamento di dump della memoria (LSASS), abuso di credenziali (Mimikatz) e persistenza di sistema.
- **Cyber Forensics**: Isolamento e decodifica di script offuscati e identificazione degli Indicatori di Compromissione (IoC).
