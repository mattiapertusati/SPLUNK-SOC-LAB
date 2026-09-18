# Detection Rule: Inhibit System Recovery (Volume Shadow Copy Deletion)

## Objective
Detect the deletion of operating system backup copies (Volume Shadow Copies). This action is classified as highly suspicious, as it is performed almost systematically by Ransomware during the early stages of infection to prevent the victim from restoring original files after encryption.

## MITRE ATT&CK Mapping
* **Tactic:** Impact (TA0040)
* **Technique:** Inhibit System Recovery (T1490)

## Alert Metadata
* **Severity:** CRITICAL
* **Confidence:** High
* **False Positives:** Extraordinary disk maintenance activities performed by legitimate system administrators.

---

## Splunk Query (SPL)
*Search covering not only vssadmin, but also wmic and wbadmin, alternative tools known to achieve the same malicious result.*

```splunk
index=wineventlog EventCode=4688 earliest=-24h (NewProcessName="*\\vssadmin.exe" OR NewProcessName="*\\wmic.exe" OR NewProcessName="*\\wbadmin.exe") CommandLine="*delete*" CommandLine="*shadow*"
| table _time, host, User, NewProcessName, CommandLine
```

## Microsoft Sentinel Query (KQL)

```kql
SecurityEvent
| where EventID == 4688 and TimeGenerated > ago(24h)
| where NewProcessName endswith "vssadmin.exe" or NewProcessName endswith "wmic.exe" or NewProcessName endswith "wbadmin.exe"
| where CommandLine contains "delete" and CommandLine contains "shadow"
| project TimeGenerated, Computer, Account, NewProcessName, CommandLine
```

## Sigma Rule (YAML)

```sigma
title: Inhibit System Recovery - Volume Shadow Copy Deletion
id: a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d
status: experimental
description: Detects the execution of commands to delete volume shadow copies, a typical behavior of ransomware.
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
    - Scheduled disk cleanup tasks or system administrators (requires immediate investigation).
level: critical
```

---

## L1 Triage Playbook (Analyst Response Steps)

When this alert triggers on the SIEM, indicating a potential active Ransomware attack (local backup destruction phase), the L1 analyst must immediately execute the following operational steps:

### 1. Process Activity Verification (Live Response)
Use the EDR Live Terminal console to connect to the compromised host. Verify if the malicious process is still running. Analyze real-time system metrics: a prolonged and unusual CPU and Disk utilization (100%) indicates a probable ongoing file encryption. Terminate (kill) any anomalous or unrecognized processes immediately.

### 2. Alternative and Offline Backup Verification
Interface with the IT team or check corporate backup tool dashboards (such as Veeam, isolated NAS servers) to verify the existence of recent, intact physical copies or system images. Additionally, check Cloud versioning (such as OneDrive/SharePoint) for user files. Prepare for recovery, keeping in mind the potential loss of the data delta generated after the last useful backup.

### 3. Network Isolation of the Device
Proceed in parallel with the logical isolation of the host using the "Isolate Host" feature of the EDR console. This will block all incoming and outgoing network communications (including access to shared network drives), preventing ransomware Lateral Movement, while keeping the encrypted EDR management channel active to allow the SOC to safely continue investigations.

### 4. Escalation to L2 with IoC List and Report
Open an Incident Response ticket for the L2 level (Escalation), including a structured operational and technical summary:
* **Context and Actions (Summary):** Report the isolated host, metrics status (CPU/Disk), any manually terminated processes, and the status of available offline backups.
* **IoCs for Threat Hunting:** Provide technical data for large-scale searching, including: Hostname and IP address of the infected machine, compromised user account, exact timestamp of the event, the detected malicious command line, and the hash (SHA256) of the process that invoked the Shadow Copies deletion.
