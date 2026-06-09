# 🛡️ Detection Engineering & SOC Analyst Portfolio

Benvenuto nel mio progetto pratico di Detection Engineering! 
In questo repository ho costruito da zero un ambiente di laboratorio (basato su DetectionLab) per simulare scenari di attacco reali, raccogliere la telemetria centralizzata e sviluppare logiche difensive all'interno di **Splunk**.

## 🚀 Panoramica del Progetto
L'obiettivo di questo progetto è dimostrare competenze pratiche nelle operazioni di un Security Operations Center (SOC) e nel Blue Teaming. Ho ricreato l'intero ciclo di vita della difesa: dall'ingegnerizzazione dell'infrastruttura di log, all'esecuzione degli attacchi, fino alla scrittura di allarmi e dashboard.

**Competenze dimostrate:**
* **SIEM & Log Management:** Configurazione e utilizzo di Splunk Enterprise.
* **Windows Security:** Analisi di Windows Event Logs, Sysmon e Windows Event Forwarding (WEF).
* **Threat Detection:** Sviluppo di query SPL avanzate basate sulle tecniche del framework **MITRE ATT&CK**.
* **Detection as Code:** Gestione degli allarmi tramite file di configurazione (`savedsearches.conf`).
* **Data Visualization:** Creazione di Dashboard interattive (XML) per il triage rapido.

---

## 📂 Struttura del Repository

Ho organizzato il progetto in moduli chiari per facilitare la navigazione. Clicca sulle singole cartelle per esplorare i dettagli:

* [**`/detections`**](./detections/): Contiene la documentazione dettagliata di 10 casi d'uso di sicurezza (Use Cases). Per ogni minaccia ho mappato l'EventCode, la tecnica MITRE e la query SPL necessaria per individuarla.
* [**`/alerts`**](./alerts/): Contiene il file `savedsearches.conf` che automatizza le detections in Splunk (Detection as Code), trasformando le query in allarmi schedulati con azioni specifiche.
* [**`/dashboards`**](./dashboards/): Contiene il codice sorgente XML (`SOC_Overview.xml`) del cruscotto operativo creato per gli analisti L1, con metriche, grafici a torta e timeline degli attacchi.
* [**`/infrastructure`**](./infrastructure/): Contiene la documentazione sull'infrastruttura di rete, il flusso dei log e il diagramma dell'ambiente Vagrant/VirtualBox utilizzato per i test.
* [**`/sigma`**](./sigma/): Contiene 5 detection tradotte in formato SIGMA per uso generale e didattico.
* [**`/kql`**](./kql/): Contiene 5 detection tradotte in formato KQL per uso generale e didattico.


---

## ⚔️ Le Minacce Simulate
Durante il laboratorio, ho simulato e rilevato con successo le seguenti attività malevole:
1. Esecuzione di **PowerShell Offuscato** (Base64).
2. Creazione di **Utenti Locali** per persistenza.
3. **Privilege Escalation** (Aggiunta al gruppo Administrators).
4. Disattivazione di **Windows Defender**.
5. Creazione di **Scheduled Tasks** malevoli.
6. Dumping della memoria **LSASS** (Estrazione Credenziali).
7. Movimento Laterale tramite **PsExec**.
8. Manipolazione delle regole del **Firewall** (Netsh).
9. **Log Clearing** (Cancellazione tracce / EventCode 1102).
10. **RDP Session Hijacking** tramite utility `tscon`.

---

## 🛠️ Strumenti Utilizzati
* **Virtualizzazione:** Vagrant, Oracle VirtualBox
* **Sistemi Operativi:** Windows 10, Windows Server 2016
* **Telemetria & SIEM:** Splunk Enterprise, Windows Event Forwarder, Sysmon
* **Frameworks:** MITRE ATT&CK

> *Progetto realizzato come dimostrazione pratica per ruoli di SOC Analyst / Detection Engineer.*
