# Detection Rule: Rundll32 Proxy Execution

## Objective
Detect the abuse of the legitimate Windows binary `rundll32.exe` to execute malicious code (Proxy Execution). Attackers often use Rundll32 to load malicious DLLs, masking them behind a trusted system process to bypass preventive controls (such as AppLocker). This rule identifies the execution of Rundll32 from suspicious directory paths (dropper locations), excluding known system parent processes.

## MITRE ATT&CK Mapping
* **Tactic:** Defense Evasion (TA0005)
* **Technique:** System Binary Proxy Execution: Rundll32 (T1218.011)

## Alert Metadata
* **Severity:** HIGH
* **Confidence:** Medium
* **False Positives:** Third-party software installers or old legacy applications that use Rundll32 in a non-standard way from temporary paths.

---

## Splunk Query (SPL)
*Filtering on directories typically used by malware to drop payloads (Users, Temp, ProgramData), excluding legitimate parent processes like explorer, svchost, and msiexec.*

```splunk
index=sysmon EventCode=1 earliest=-24h Image="*\\rundll32.exe" NOT (ParentImage="*\\svchost.exe" OR ParentImage="*\\msiexec.exe" OR ParentImage="*\\explorer.exe") (CommandLine="*\\Users\\*" OR CommandLine="*\\Temp\\*" OR CommandLine="*\\ProgramData\\*")
| table _time, host, User, CommandLine, ParentImage, ParentCommandLine
```

## Microsoft Sentinel Query (KQL)

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

## Sigma Rule (YAML)

```sigma
title: Detection of Anomalous Rundll32 Executions
id: 550e8400-e29b-41d4-a716-446655440000
status: experimental
description: Identifies the execution of rundll32.exe from unusual paths or with suspicious parents (possible malicious DLL execution or dropper).
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
    - Legitimate administrative activities or software installations.
level: medium
```

---

## L1 Triage Playbook (Analyst Response Steps)

When this alert triggers, it indicates the potential abuse of a system binary (Living off the Land) to hide the execution of malicious code or download secondary payloads. The L1 analyst must follow these steps:

### 1. Execution Chain and Payload Analysis (Initial Triage)
Analyze the process logs to reconstruct the execution context:
* **Verify the `ParentImage`:** Determine the origin of the attack. If the parent process is an Office application (such as `winword.exe`) or a browser, it likely indicates Phishing or a drive-by download.
* **Examine the `CommandLine`:** Identify the exact path of the loaded DLL. Confirm whether it resides in anomalous folders for system libraries (such as `C:\Users\`, `C:\Temp\`, `C:\ProgramData\`).
* **OSINT Analysis:** Extract the hash (SHA256) of the DLL or analyze the file name and verify its reputation on threat intelligence platforms (such as VirusTotal).

### 2. Dropper Behavior Analysis (Network & File System)
Verify if `rundll32.exe` is acting as a downloader/dropper by analyzing subsequent events:
* **Network Events:** Check EDR telemetry to detect suspicious outbound connections initiated by `rundll32.exe` toward unknown IPs or domains (potential contact with a Command & Control server).
* **File Events:** Search for file creation events (*DeviceFileEvents*), paying attention to new executables or scripts dropped onto the disk immediately after the network connection.

### 3. Containment and Isolation (Host Isolation)
If the malicious behavior is confirmed (True Positive), proceed immediately with the logical network isolation of the host via the EDR console. This will prevent the process from contacting the C2 server or performing lateral movements, while keeping the remote investigative channel intact. Access Live Response and terminate the involved process tree (parent and children).

### 4. Escalation to L2 with IoC List and Report
Open an Incident Response ticket for the L2 level (Escalation) structured as follows:
* **Context and Actions:** Report the isolated host, the blocked infected process, and confirm if the attack originated from an Office file/Email.
* **IoCs for Threat Hunting:** Provide technical data for large-scale searching, including: 
  * External IP addresses / Domains contacted (C2).
  * Hashes (SHA256) of the dropped files (malicious DLL, secondary payloads).
  * The exact command line used to bypass controls.
  * The path of the files written to the disk.
