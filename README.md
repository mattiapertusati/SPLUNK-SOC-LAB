![CompTIA Security+](https://img.shields.io/badge/CompTIA-Security%2B-FF0000?style=flat&logo=comptia)
![Splunk](https://img.shields.io/badge/Splunk-SIEM-black?style=flat&logo=splunk)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=flat)
![Python](https://img.shields.io/badge/Python-3.x-blue?style=flat&logo=python)
![Microsoft Sentinel](https://img.shields.io/badge/Microsoft-Sentinel-0078D4?style=flat&logo=microsoft)

# 🛡️ Advanced Detection Engineering & Threat Hunting Portfolio

Benvenuto nel mio portfolio aziendale di Detection Engineering. Questo repository dimostra un ciclo di vita completo di una detection: dalla simulazione dell'attacco (Red Teaming) alla raccolta della telemetria, fino alla scrittura e validazione della regola di rilevamento in configurazioni multi-vendor (Splunk SPL, Microsoft Sentinel KQL, e Sigma).

L'intero progetto è stato sviluppato all'interno di un ambiente controllato (**DetectionLab**) enterprise-grade composto da un Domain Controller, macchine client Windows 10 monitorate via Sysmon e Windows Event Forwarding (WEF), e un'istanza centrale Splunk (Logger).

---

## 🎯 Project Metrics (At a Glance)

* **15** SPL Detections (Splunk)
* **15** KQL Detections (Microsoft Sentinel)
* **15** Vendor-Agnostic SIGMA Rules
* **5** Advanced Correlation Rules (Chain Detections)
* **10** Attack Validations (Atomic Red Team & Native OS)
* **1** Threat Model Framework Enterprise
* **1** Live SOC Executive Dashboard (Splunk XML)
* **1** DetectionLab Environment (Active Directory, WEF, Sysmon)

---

## 📊 Sezione Numerica sui Risultati & Performance Metrics

I dati seguenti rappresentano i risultati quantitativi ricavati dalle sessioni di validazione e stress-test eseguiti in laboratorio tramite **Atomic Red Team** e comandi OS nativi. Le metriche di performance sono calcolate sulla base di una baseline di traffico ordinario misurato in 48 ore di attività simulata della rete (circa 150.000 eventi totali).

### 📈 KPI di Efficacia della Rilevazione

* **Tecniche Rilevate e Validate:** 10 / 10 Scenari Critici
* **True Positives (TP) generati in Lab:** 26 (attacchi lanciati con varianti diverse)
* **False Positives (FP) intercettati in Baseline:** 1 (script di monitoraggio IT legittimo)
* **Precisione Globale (Precision):** **96.2%** $$\text{Precision} = \frac{\text{TP}}{\text{TP} + \text{FP}} = \frac{26}{26 + 1} = 96.2\%$$
* **Sensibilità Stimata (Recall):** **92.8%** *(Calcolata testando 28 varianti totali di attacco, di cui 26 hanno attivato la regola).*
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

---

## 🗺️ MITRE ATT&CK Coverage Matrix

La seguente matrice illustra la copertura tattica delle 15 regole di rilevamento (e delle 5 chain-detections) sviluppate all'interno del laboratorio. Mappare le detection sull'Enterprise MITRE ATT&CK Framework permette di avere una visione olistica della *Security Posture* e di identificare le priorità per i futuri cicli di sviluppo.

| MITRE ID | Tattica (Tactic) | Regole Sviluppate (Coverage) | Stato Copertura |
| :--- | :--- | :---: | :---: |
| **TA0001** | Initial Access | 1 | 🟡 |
| **TA0002** | Execution | 4 | 🟢 |
| **TA0003** | Persistence | 3 | 🟢 |
| **TA0004** | Privilege Escalation | 1 | 🟡 |
| **TA0005** | Defense Evasion | 5 | 🟢 |
| **TA0006** | Credential Access | 1 | 🟡 |
| **TA0007** | Discovery | 0 | ⚪ (Blind Spot) |
| **TA0008** | Lateral Movement | 2 | 🟢 |
| **TA0009** | Collection | 1 | 🟡 |
| **TA0011** | Command and Control | 1 | 🟡 |
| **TA0010** | Exfiltration | 1 | 🟡 |
| **TA0040** | Impact | 1 | 🟡 |

*(Nota: La presenza di "Blind Spots" come la tattica Discovery è stata intenzionalmente mantenuta per riflettere un ambiente in continua evoluzione, dove il focus del primo ciclo di Detection Engineering è stato posto sulle tecniche post-exploitation ad alto impatto (Defense Evasion, Execution e Persistence).*

---

## 🏗️ Architettura del Laboratorio di Validazione

Il flusso dei dati segue un'architettura rigorosa e centralizzata per garantire che nessuna telemetria venga persa durante le fasi di attacco:

$$\text{Atomic Red Team / Attaccante} \longrightarrow \text{Windows Endpoint (Sysmon/Security Log)} \longrightarrow \text{Windows Event Forwarder (WEF)} \longrightarrow \text{Splunk Forwarder} \longrightarrow \text{Splunk Enterprise (SIEM)}$$

1.  **Attack Generation:** I test vengono eseguiti programmaticamente tramite `Invoke-AtomicTest` o comandi OS consolidati.
2.  **Telemetry Collection:** Viene abilitato l'auditing avanzato di Windows (Process Creation 4688 con CommandLine abilitata) accoppiato a una configurazione Sysmon ottimizzata (basata su SwiftOnSecurity).
3.  **Log Forwarding:** I log vengono centralizzati via WEF e indicizzati in Splunk sotto l'index `wineventlog` e `sysmon`.

---

## 📁 Struttura del Repository

* `detections/`: Contiene le logiche e le definizioni approfondite delle query in SPL per Splunk.
* `kql/`: Repository delle regole convertite e ottimizzate per **Microsoft Sentinel**.
* `sigma/`: Regole in formato standard **Sigma (YAML)** per la massima portabilità.
* `validation_reports/`: I 10 report dettagliati contenenti i comandi eseguiti, l'analisi degli Event ID e gli screenshot di validazione presi direttamente dal SIEM.
* `THREAT_MODEL.md`: Analisi dei profili di rischio, della superficie di attacco e della strategia difensiva adottata per la stesura delle detection.
