# Detection Rule: Kerberoasting Attack (Service Ticket Request)

## Objective
Detect requests for Kerberos Service Tickets (TGS) that use weak RC4 encryption (0x17). An attacker requests this type of ticket to export it and attempt offline password cracking. Legitimate machine accounts are excluded from this search.

## MITRE ATT&CK Mapping
* **Tactic:** Credential Access (TA0006)
* **Technique:** Steal or Forge Kerberos Tickets: Kerberoasting (T1558.003)

## Alert Metadata
* **Severity:** HIGH
* **Confidence:** High
* **False Positives:** Legacy systems that do not support AES, incorrect domain configurations.

---

## Splunk Query (SPL)
*Optimization: The explicit use of the `fields` command before aggregations instructs the SIEM to discard unnecessary data immediately, drastically reducing RAM and CPU usage during the search.*

```splunk
index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17 NOT Account_Name="*$"
| fields Account_Name, Service_Name, Client_Address
| stats count by Account_Name, Service_Name, Client_Address
```

## Microsoft Sentinel Query (KQL)
Literal translation of the SPL logic. It uses `endswith` to isolate machine accounts (which always end with the  character) with absolute precision, avoiding the exclusion of legitimate users who might have a  inside their name.

```kql
SecurityEvent
| where EventID == 4769
| where TicketEncryptionType == "0x17"
| where Account !endswith "\$"
| project Account, ServiceName, IpAddress
| summarize count() by Account, ServiceName, IpAddress
```

## Sigma Rule (YAML)

```sigma
title: Detection of Kerberos Tickets with Weak Encryption (RC4)
id: 56bff535-49e2-4734-9f44-f76d7feaadeb
status: experimental
description: Detects requests for Kerberos service tickets (TGS) that use weak RC4 encryption (0x17), excluding machine accounts.
references:
    - [https://mitre.org](https://mitre.org)
author: Mattia
date: 2026/06/22
tags:
    - attack.credential_access
    - attack.t1558.003
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4769
        TicketEncryptionType: '0x17'
    filter_machine_accounts:
        TargetUserName|endswith: '\$'
    condition: selection and not filter_machine_accounts
falsepositives:
    - Legacy systems that do not support AES
    - Incorrect domain configurations
level: medium
```
