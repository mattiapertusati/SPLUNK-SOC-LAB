# SOC & Detection Engineering Lab

This project is a laboratory environment (DetectionLab) built to simulate real-world attacks on Windows systems, collect telemetry, and develop custom Detection and Alerting logic within a SIEM (Splunk).

## Project Objectives
- Configure a centralized logging infrastructure (Windows Event Forwarding -> Splunk).
- Simulate real attack techniques based on the MITRE ATT&CK framework.
- Develop **Detection as Code** by creating operational alerts and dashboards for a Security Operations Center (SOC).

---

## Architecture and Data Flow

The infrastructure is based on virtual machines managed via Vagrant. The laboratory logic is divided into two main flows:
1. **Offensive Flow:** The attacker targets endpoints (Win10) or the Domain Controller (DC). Malicious actions generate local logs.
2. **Defensive Flow:** Logs are forwarded via WinRM to the WEF (Windows Event Forwarder) server and finally centralized on Splunk (Logger). From here, the SOC team monitors events, manages alerts, and analyzes dashboards.

```mermaid
graph TD
    classDef attacker fill:#2d3436,stroke:#ff7675,stroke-width:2px,color:#fff;
    classDef windows fill:#0984e3,stroke:#74b9ff,stroke-width:2px,color:#fff;
    classDef splunk fill:#00b894,stroke:#55efc4,stroke-width:2px,color:#fff;
    classDef soc fill:#6c5ce7,stroke:#a29bfe,stroke-width:2px,color:#fff;

    A[Attacker / Red Team]:::attacker

    subgraph "DetectionLab Environment"
        direction TB
        W10[WIN10<br/>Victim Endpoint]:::windows
        DC[DC<br/>Domain Controller]:::windows
        WEF[WEF<br/>Windows Event Forwarder]:::windows
        SPLUNK[LOGGER<br/>Splunk Enterprise]:::splunk
    end

    SOC[SOC Analyst / Blue Team]:::soc

    %% Attack Flow
    A -. "Attacks (RDP, PsExec, PowerShell)" .-> W10
    A -. "Enumeration" .-> DC

    %% Log Flow (Telemetry)
    W10 -- "Event Forwarding (WinRM)" --> WEF
    DC -- "Event Forwarding (WinRM)" --> WEF
    WEF -- "Centralized Logs" --> SPLUNK

    %% Monitoring
    SOC -- "Alert & Dashboard Management" --> SPLUNK
```
