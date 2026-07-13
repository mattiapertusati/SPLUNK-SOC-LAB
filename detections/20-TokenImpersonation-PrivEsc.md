# 🚨 Detection Rule: Access Token Manipulation (Impersonation)

## 📋 Obiettivo
Rilevare l'assegnazione di privilegi speciali (Special Logon) ad account non standard. L'attacco di Token Impersonation si verifica quando un attaccante ruba o duplica il token di sicurezza di un altro processo con privilegi elevati, permettendogli di eseguire azioni per conto di quell'utente senza dover conoscere le credenziali.

I privilegi maggiormente abusati e monitorati in questa regola sono:
* **SeImpersonatePrivilege:** Permette a un programma di impersonare temporaneamente un utente.
* **SeAssignPrimaryTokenPrivilege:** Permette di assegnare token di accesso a un nuovo processo (spesso usato in combo con SeImpersonate).
* **SeDebugPrivilege:** Consente l'ispezione della memoria di altri processi (abusato da tool come Mimikatz per leggere le password in LSASS).
* **SeTcbPrivilege:** Il privilegio più alto (Trusted Computer Base), che permette a un processo di agire come parte del nucleo del sistema operativo.

*Nota: Per generare questa telemetria in laboratorio, è necessario abilitare l'auditing avanzato di Windows tramite il comando: `auditpol /set /subcategory:"Special Logon" /success:enable`.*

## 🎯 MITRE ATT&CK Mapping
* **Tactic:** Privilege Escalation (TA0004), Defense Evasion (TA0005)
* **Technique:** Access Token Manipulation: Token Impersonation/Theft (T1134.001)

## 🚦 Alert Metadata
* **Severity:** HIGH
* **Confidence:** Medium
* **False Positives:** Servizi di backup aziendali, software di monitoraggio di sistema legittimi o account di servizio amministrativi (Service Accounts).

---

## 🟢 Splunk Query (SPL)
*Ricerca ottimizzata filtrando immediatamente gli account macchina e SYSTEM nella ricerca di base, per poi isolare i privilegi critici.*

```splunk
index=wineventlog EventCode=4672 earliest=-24h NOT (SubjectUserName="SYSTEM" OR SubjectUserName="*$") (PrivilegeList="*SeDebugPrivilege*" OR PrivilegeList="*SeTcbPrivilege*" OR PrivilegeList="*SeImpersonatePrivilege*" OR PrivilegeList="*SeAssignPrimaryTokenPrivilege*")
| table _time, host, SubjectUserName, PrivilegeList
```

## 🔵 Microsoft Sentinel Query (KQL)
*Sintassi ottimizzata tramite l'uso dell'operatore has per la ricerca all'interno della stringa dei privilegi, escludendo gli account di sistema.*

```kql
SecurityEvent
| where EventID == 4672 and TimeGenerated > ago(24h)
| where SubjectUserName != "SYSTEM" and SubjectUserName !endswith "$"
| where (PrivilegeList has "SeImpersonatePrivilege" or PrivilegeList has "SeAssignPrimaryTokenPrivilege" or PrivilegeList has "SeDebugPrivilege" or PrivilegeList has "SeTcbPrivilege")
| project TimeGenerated, Computer, SubjectUserName, PrivilegeList
```

## 🟡 Sigma Rule (YAML)

```sigma
title: Rilevamento Token Impersonation - Privilegi Speciali
id: 4a2b3c4d-e5f6-7a8b-9c0d-1e2f3a4b5c6d
status: experimental
description: Rileva l'assegnazione di privilegi speciali (SeImpersonate, SeDebug, ecc.) a utenti non standard per identificare tentativi di Token Impersonation.
author: Mattia
date: 2026/07/13
references:
    - [https://mitre.org](https://mitre.org)
tags:
    - attack.privilege_escalation
    - attack.defense_evasion
    - attack.t1134.001
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4672
        PrivilegeList|contains:
            - 'SeImpersonatePrivilege'
            - 'SeAssignPrimaryTokenPrivilege'
            - 'SeDebugPrivilege'
            - 'SeTcbPrivilege'
    filter_system:
        SubjectUserName: 'SYSTEM'
    filter_machine:
        SubjectUserName|endswith: '$'
    condition: selection and not 1 of filter_*
falsepositives:
    - Software di backup e ripristino di sistema.
    - Amministratori di dominio che eseguono task di manutenzione avanzata.
level: high
```
