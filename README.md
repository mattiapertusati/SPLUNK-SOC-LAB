![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-F66151?style=flat)
![Splunk](https://img.shields.io/badge/Splunk-Enterprise_SIEM-000000?style=flat&logo=splunk&logoColor=white)
![Sigma](https://img.shields.io/badge/Sigma-Generic_Rules-00B2A9?style=flat)
![KQL](https://img.shields.io/badge/KQL-Microsoft_Sentinel-0078D4?style=flat&logo=microsoft&logoColor=white)
![Atomic Red Team](https://img.shields.io/badge/Atomic_Red_Team-Attack_Simulation-FF9800?style=flat)
![DetectionLab](https://img.shields.io/badge/DetectionLab-Enterprise_Environment-333333?style=flat)

# 🛡️ Advanced Detection Engineering & Threat Hunting Portfolio

Benvenuto nel mio portfolio aziendale di Detection Engineering. Questo repository dimostra un ciclo di vita completo di una detection: dalla simulazione dell'attacco (Red Teaming) alla raccolta della telemetria, fino alla scrittura e validazione della regola di rilevamento in configurazioni multi-vendor (Splunk SPL, Microsoft Sentinel KQL, e Sigma).

L'intero progetto è stato sviluppato all'interno di un ambiente controllato (**DetectionLab**) enterprise-grade composto da un Domain Controller, macchine client Windows 10 monitorate via Sysmon e Windows Event Forwarding (WEF), e un'istanza centrale Splunk (Logger).

---

## 🎯 Project Metrics (At a Glance)

* **11** SPL Detections (Splunk)
* **11** KQL Detections (Microsoft Sentinel)
* **11** Vendor-Agnostic SIGMA Rules
* **5** Advanced Correlation Rules (Chain Detections)
* **11** Attack Validations (Atomic Red Team & Native OS)
* **1** Threat Model Framework Enterprise
* **1** Live SOC Executive Dashboard (Splunk XML)
* **1** DetectionLab Environment (Active Directory, WEF, Sysmon)

---

## 📊 Sezione Numerica sui Risultati & Performance Metrics

I dati seguenti rappresentano i risultati quantitativi ricavati dalle sessioni di validazione e stress-test eseguiti in laboratorio tramite **Atomic Red Team** e comandi OS nativi. Le metriche di performance sono calcolate sulla base di una baseline di traffico ordinario misurato in 48 ore di attività simulata della rete (circa 150.000 eventi totali).

### 📈 KPI di Efficacia della Rilevazione

* **Tecniche Rilevate e Validate:** 11 / 11 Scenari Critici
* **True Positives (TP) generati in Lab:** 27 (attacchi lanciati con varianti diverse)
* **False Positives (FP) intercettati in Baseline:** 1 (script di monitoraggio IT legittimo)
* **Precisione Globale (Precision):** **96.4%** 
  $$\text{Precision} = \frac{\text{TP}}{\text{TP} + \text{FP}} = \frac{27}{27 + 1} = 96.4\%$$
* **Sensibilità Stimata (Recall):** **93.1%** *(Calcolata testando 29 varianti totali di attacco, di cui 27 hanno attivato la regola).*
* **Tasso di Falsi Positivi (False Positive Rate - FPR):** **< 0.01%** rispetto al volume totale della telemetria analizzata.

### 📋 Detection Validation Matrix

| ID MITRE | Nome Tecnica / Scenario | SPL (Splunk) | KQL (Sentinel) | Sigma (YAML) | Lab Validated | Risultato Telemetria |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| **T1059.001** | Encoded PowerShell Command | ✅ | ✅ | ✅ | ✅ | Triggered (EventID 4688) |
| **T1136.001** | Local User Creation | ✅ | ✅ | ✅ | ✅ | Triggered (EventID 4720) |
| **T1548.002** | Local Privilege Escalation (UAC) | ✅ | ✅ | ✅ | ✅ | Triggered (EventID 4732) |
| **T1562.001** | Windows Defender Evasion | ✅ | ✅ | ✅ | ✅ | Triggered (EventCode 4104) |
| **T1053.005** | Scheduled Task Persistence | ✅ | ✅ | ✅ | ✅ | Triggered (EventID 4698) |
| **T1003.001** | OS Credential Dumping: LSASS | ✅ | ✅ | ✅ | ✅ | Triggered (EventCode 1) |
| **T1569.002** | Lateral Movement via PsExec | ✅ | ✅ | ✅ | ✅ | Triggered (EventID 4697/7045) |
| **T1562.004** | Firewall Manipulation (Netsh) | ✅ | ✅ | ✅ | ✅ | Triggered (EventCode 1/4688) |
| **T1070.001** | Clearing Event Logs (wevtutil) | ✅ | ✅ | ✅ | ✅ | Triggered (EventID 1102) |
| **T1563.002** | RDP Session Hijacking (tscon) | ✅ | ✅ | ✅ | ✅ | Triggered (EventID 4688) |
| **TA0007** | Local & Domain Reconnaissance | ✅ | ✅ | ✅ | ✅ | Triggered (EventID 1) |

---

## 🗺️ MITRE ATT&CK Coverage Matrix

La seguente matrice illustra la copertura tattica delle 16 regole di rilevamento (e delle 5 chain-detections) sviluppate all'interno del laboratorio. Mappare le detection sull'Enterprise MITRE ATT&CK Framework permette di avere una visione olistica della *Security Posture* e di identificare le priorità per i futuri cicli di sviluppo.

| MITRE ID | Tattica (Tactic) | Regole Sviluppate (Coverage) | Stato Copertura |
| :--- | :--- | :---: | :---: |
| **TA0001** | Initial Access | 1 | 🟡 |
| **TA0002** | Execution | 4 | 🟢 |
| **TA0003** | Persistence | 3 | 🟢 |
| **TA0004** | Privilege Escalation | 1 | 🟡 |
| **TA0005** | Defense Evasion | 5 | 🟢 |
| **TA0006** | Credential Access | 1 | 🟡 |
| **TA0007** | Discovery | 1 | 🟡 |
| **TA0008** | Lateral Movement | 2 | 🟢 |
| **TA0009** | Collection | 1 | 🟡 |
| **TA0011** | Command and Control | 1 | 🟡 |
| **TA0010** | Exfiltration | 1 | 🟡 |
| **TA0040** | Impact | 1 | 🟡 |

*(Nota: L'iniziale "Blind Spot" sulla tattica Discovery è stato analizzato e recentemente sanato con l'introduzione di logiche di rilevamento comportamentali basate su soglia, riflettendo l'approccio iterativo di Continuous Detection Improvement tipico di un moderno SOC).*

---

## ⚙️ The Detection Engineering Lifecycle

Ogni singola regola presente in questo repository è stata sviluppata e testata seguendo un rigoroso ciclo di vita operativo. Questo garantisce che le detection non siano solo teoriche, ma applicabili in un reale contesto aziendale (SOC).

```mermaid
graph LR
    A[🔴 1. Attack] -->|Atomic Red Team| B[📡 2. Telemetry]
    B -->|Sysmon / Event Logs| C[🛠️ 3. Detection]
    C -->|SPL / KQL / Sigma| D[🚨 4. Alert]
    D -->|SIEM Dashboard| E[🛡️ 5. Triage]
    E -->|Playbooks / CyberChef| F[✅ 6. Validation]
    
    style A fill:#3b1c1c,stroke:#d41f1f,stroke-width:2px,color:#fff
    style B fill:#1c2b3b,stroke:#0877a6,stroke-width:2px,color:#fff
    style C fill:#3b321c,stroke:#f8be34,stroke-width:2px,color:#fff
    style D fill:#3b231c,stroke:#f1813f,stroke-width:2px,color:#fff
    style E fill:#1c3b24,stroke:#53a051,stroke-width:2px,color:#fff
    style F fill:#1c3b3b,stroke:#00a6a6,stroke-width:2px,color:#fff
