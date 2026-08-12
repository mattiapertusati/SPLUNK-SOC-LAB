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

* **22** SPL Detections (Splunk)
* **17** KQL Detections (Microsoft Sentinel)
* **16** Vendor-Agnostic SIGMA Rules
* **5** Advanced Correlation Rules (Chain Detections)
* **17** Attack Validations (Atomic Red Team & Native OS)
* **1** Threat Model Framework Enterprise
* **1** Live SOC Executive Dashboard (Splunk XML)
* **1** DetectionLab Environment (Active Directory, WEF, Sysmon, Linux Auditd)

---

## 🗺️ MITRE ATT&CK Coverage Matrix

*Nota: Le regole sono state mappate esclusivamente in base alla loro **Tattica Primaria** per mantenere la coerenza statistica (Totale: 17 scenari di base).*

| MITRE ID | Tattica (Tactic) | Regole Sviluppate (Primary) | Stato Copertura |
| :--- | :--- | :---: | :---: |
| **TA0001** | Initial Access | 0 | ⚪ |
| **TA0002** | Execution | 3 | 🟢 |
| **TA0003** | Persistence | 2 | 🟢 |
| **TA0004** | Privilege Escalation | 3 | 🟢 |
| **TA0005** | Defense Evasion | 4 | 🟢 |
| **TA0006** | Credential Access | 2 | 🟢 |
| **TA0007** | Discovery | 1 | 🟡 |
| **TA0008** | Lateral Movement | 1 | 🟡 |
| **TA0009** | Collection | 0 | ⚪ |
| **TA0011** | Command and Control | 0 | ⚪ |
| **TA0010** | Exfiltration | 0 | ⚪ |
| **TA0040** | Impact | 1 | 🟡 |

---

## 📊 Performance Metrics & Validation

### 📈 KPI di Efficacia della Rilevazione
* **Tecniche Rilevate e Validate:** 17 / 17 Scenari Critici
* **True Positives (TP) generati in Lab:** 35 (attacchi lanciati con varianti diverse)
* **False Positives (FP) intercettati in Baseline:** 1 (script di monitoraggio IT legittimo)
* **Precisione Globale (Precision):** **97.2%**
* **Tasso di Falsi Positivi (False Positive Rate - FPR):** **< 0.01%** rispetto al volume totale della telemetria analizzata.

### 📋 Detection Validation Matrix

| File / MITRE | Nome Tecnica / Scenario | SPL | KQL | Sigma | Playbook L1 |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **01 (T1059.001)** | Encoded PowerShell Command | ✅ | ✅ | ✅ | ✅ |
| **02 (T1136.001)** | Local User Creation | ✅ | ✅ | ✅ | ✅ |
| **03 (T1548.002)** | Local Privilege Escalation (UAC) | ✅ | ✅ | ✅ | ✅ |
| **04 (T1562.001)** | Windows Defender Evasion | ✅ | ✅ | ✅ | ✅ |
| **05 (T1053.005)** | Scheduled Task Persistence | ✅ | ✅ | ✅ | ✅ |
| **06 (T1003.001)** | OS Credential Dumping: LSASS | ✅ | ✅ | ✅ | ✅ |
| **07 (T1569.002)** | Lateral Movement via PsExec | ✅ | ✅ | ✅ | ✅ |
| **08 (T1562.004)** | Firewall Manipulation (Netsh) | ✅ | ✅ | ✅ | ✅ |
| **09 (T1070.001)** | Clearing Event Logs (wevtutil) | ✅ | ✅ | ✅ | ✅ |
| **10 (T1563.002)** | RDP Session Hijacking (tscon) | ✅ | ✅ | ✅ | ✅ |
| **16 (TA0007)** | Local & Domain Reconnaissance | ✅ | ✅ | ✅ | ✅ |
| **17 (T1558.003)** | Kerberoasting (RC4 TGS Request) | ✅ | ✅ | ✅ | ✅ |
| **18 (T1548.001)** | Linux SUID Discovery & PrivEsc | ✅ | ✅ | ✅ | ✅ |
| **19 (T1047)** | WMI Lateral Movement & Execution | ✅ | ✅ | ✅ | ✅ |
| **20 (T1134.001)** | Token Impersonation (Special Logon)| ✅ | ✅ | ✅ | ✅ |
| **21 (T1490)** | Inhibit System Recovery (VSS Deletion) | ✅ | ✅ | ✅ | ✅ |
| **22 (T1218.011)** | Rundll32 Proxy Execution (Droppers) | ✅ | ✅ | ⚪ | ✅ |

### 🔗 Advanced Correlation Rules
Oltre alle detection di base, sono state sviluppate 5 regole di correlazione avanzata in SPL per tracciare attacchi complessi (Kill Chain):
* `11` - Domain Compromise Correlation
* `12` - Credential Theft Correlation
* `13` - Lateral Persistence Correlation
* `14` - Ransomware & Exfiltration Correlation
* `15` - Phishing & Initial Access Correlation

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
```
1. **Attack:** Simulazione controllata dell'avversario tramite script o esecuzione manuale di tecniche MITRE.
2. **Telemetry:** Verifica che l'infrastruttura (WEF/Sysmon) abbia effettivamente generato e inoltrato i log (EventID).
3. **Detection:** Scrittura e ottimizzazione della query per isolare il comportamento malevolo minimizzando i falsi positivi.
4. **Alert:** Configurazione dei parametri di allarme (Severity, Confidence, MITRE Mapping).
5. **Triage:** Stesura del playbook operativo con le istruzioni per l'analista di primo livello (L1).
6. **Validation:** Stress-test della regola contro il traffico di baseline per calcolare metriche come Precision e Recall.

---

## 🏗️ Architettura del Laboratorio di Validazione

Il flusso dei dati segue un'architettura rigorosa e centralizzata per garantire che nessuna telemetria venga persa durante le fasi di attacco:

$$\text{Atomic Red Team / Attaccante} \longrightarrow \text{Windows Endpoint (Sysmon/Security Log)} \longrightarrow \text{Windows Event Forwarder (WEF)} \longrightarrow \text{Splunk Forwarder} \longrightarrow \text{Splunk Enterprise (SIEM)}$$

1.  **Attack Generation:** I test vengono eseguiti programmaticamente tramite `Invoke-AtomicTest` o comandi OS consolidati.
2.  **Telemetry Collection:** Viene abilitato l'auditing avanzato di Windows (Process Creation 4688 con CommandLine abilitata) accoppiato a una configurazione Sysmon ottimizzata (basata su SwiftOnSecurity).
3.  **Log Forwarding:** I log vengono centralizzati via WEF e indicizzati in Splunk sotto l'index `wineventlog` e `sysmon`.

---

## 📁 Struttura del Repository

* `detections/`: Contiene le logiche e le definizioni approfondite delle query in SPL per Splunk.
* `kql/`: Repository delle regole convertite e ottimizzate per **Microsoft Sentinel**.
* `sigma/`: Regole in formato standard **Sigma (YAML)** per la massima portabilità.
* `validation_reports/`: I 10 report dettagliati contenenti i comandi eseguiti, l'analisi degli Event ID e gli screenshot di validazione presi direttamente dal SIEM.
* `THREAT_MODEL.md`: Analisi dei profili di rischio, della superficie di attacco e della strategia difensiva adottata per la stesura delle detection.
