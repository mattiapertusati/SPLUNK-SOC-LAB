# 🚨 Detection Rule: Kerberoasting Attack (Service Ticket Request)

## 📋 Obiettivo
Rilevare la richiesta di ticket Kerberos (TGS) che utilizzano la crittografia debole RC4 (0x17). Un attaccante richiede questo tipo di ticket per poterlo esportare e tentare il cracking della password offline. Vengono esclusi dalla ricerca gli account macchina legittimi.

## 🎯 MITRE ATT&CK Mapping
* **Tactic:** Credential Access (TA0006)
* **Technique:** Steal or Forge Kerberos Tickets: Kerberoasting (T1558.003)

## 🚦 Alert Metadata
* **Severity:** HIGH
* **Confidence:** High
* **False Positives:** Sistemi legacy che non supportano AES, configurazioni errate di dominio.

---

## 🟢 Splunk Query (SPL)
*Ottimizzazione: L'uso esplicito del comando `fields` prima delle aggregazioni istruisce il SIEM a scartare immediatamente i dati inutili, abbattendo drasticamente l'uso di RAM e CPU durante la ricerca.*

```splunk
index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17 NOT Account_Name="*$"
| fields Account_Name, Service_Name, Client_Address
| stats count by Account_Name, Service_Name, Client_Address
```

## 🔵 Microsoft Sentinel Query (KQL)
Traduzione letterale della logica SPL. Utilizza `endswith` per isolare con precisione assoluta gli account macchina (che terminano sempre con il carattere $) evitando di escludere utenti legittimi che potrebbero avere un $ all'interno del nome.

```kql
SecurityEvent
| where EventID == 4769
| where TicketEncryptionType == "0x17"
| where Account !endswith "$"
| project Account, ServiceName, IpAddress
| summarize count() by Account, ServiceName, IpAddress
```

## 🟡 Sigma Rule (YAML)

```sigma
title: Rilevamento Ticket Kerberos con Crittografia Debole (RC4)
id: 56bff535-49e2-4734-9f44-f76d7feaadeb
status: experimental
description: Rileva la richiesta di ticket Kerberos (TGS) che utilizzano la crittografia debole RC4 (0x17), escludendo gli account macchina.
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
        TargetUserName|endswith: '$'
    condition: selection and not filter_machine_accounts
falsepositives:
    - Sistemi legacy che non supportano AES
    - Configurazioni errate di dominio
level: medium
```
