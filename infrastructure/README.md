# 🛡️ SOC & Detection Engineering Lab

Questo progetto è un ambiente di laboratorio (DetectionLab) costruito per simulare attacchi reali su sistemi Windows, raccogliere la telemetria e sviluppare logiche di Detection e Alerting personalizzate all'interno di un SIEM (Splunk).

## 🎯 Obiettivi del Progetto
- Configurare un'infrastruttura di logging centralizzata (Windows Event Forwarding -> Splunk).
- Simulare tecniche di attacco reali basate sul framework MITRE ATT&CK.
- Sviluppare **Detection as Code** creando allarmi e dashboard operative per un Security Operations Center (SOC).

---

## 🏗️ Architettura e Flusso dei Dati

L'infrastruttura è basata su macchine virtuali gestite tramite Vagrant. La logica del laboratorio si divide in due flussi principali:
1. **Flusso Offensivo:** L'attaccante colpisce gli endpoint (Win10) o il Domain Controller (DC). Le azioni malevole generano log locali.
2. **Flusso Difensivo:** I log vengono inoltrati tramite WinRM al server WEF (Windows Event Forwarder) e infine centralizzati su Splunk (Logger). Da qui, il team SOC monitora gli eventi, gestisce gli allarmi e analizza le dashboard.

```mermaid
graph TD
    classDef attacker fill:#2d3436,stroke:#ff7675,stroke-width:2px,color:#fff;
    classDef windows fill:#0984e3,stroke:#74b9ff,stroke-width:2px,color:#fff;
    classDef splunk fill:#00b894,stroke:#55efc4,stroke-width:2px,color:#fff;
    classDef soc fill:#6c5ce7,stroke:#a29bfe,stroke-width:2px,color:#fff;

    A[🥷 Attaccante / Red Team]:::attacker

    subgraph "DetectionLab Environment"
        direction TB
        W10[💻 WIN10<br/>Endpoint Vittima]:::windows
        DC[🏢 DC<br/>Domain Controller]:::windows
        WEF[🛡️ WEF<br/>Windows Event Forwarder]:::windows
        SPLUNK[🧠 LOGGER<br/>Splunk Enterprise]:::splunk
    end

    SOC[🧑‍💻 Analista SOC / Blue Team]:::soc

    %% Flusso di Attacco
    A -. "Attacchi (RDP, PsExec, PowerShell)" .-> W10
    A -. "Enumerazione" .-> DC

    %% Flusso dei Log (Telemetry)
    W10 -- "Inoltro Eventi (WinRM)" --> WEF
    DC -- "Inoltro Eventi (WinRM)" --> WEF
    WEF -- "Log Centralizzati" --> SPLUNK

    %% Monitoraggio
    SOC -- "Gestione Allarmi & Dashboard" --> SPLUNK
