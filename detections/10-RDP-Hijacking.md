# 🚨 Detection of RDP Session Hijacking via Tscon

### Descrizione
Rileva il tentativo di dirottare una sessione di Desktop Remoto (RDP) disconnessa o attiva utilizzando l'utility nativa di Windows `tscon.exe`. Gli attaccanti con privilegi di SYSTEM utilizzano questa tecnica per subentrare in sessioni appartenenti ad altri utenti (spesso amministratori di dominio) scavalcando completamente la necessità di conoscere o craccare la password della vittima. L'indicatore chiave è l'uso del parametro `/dest:` per reindirizzare la sessione bersaglio.

## 🎯 MITRE ATT&CK
* **Tactic:** Lateral Movement (TA0008)
* **Technique:** Remote Services (T1021)
* **Sub-technique:** Remote Desktop Protocol (T1021.001)

## 🚦 Alert Metadata
* **Severity:** Critical
* **Confidence:** High
* **Impact:** High

### Query SPL
```splunk
index=wineventlog EventCode=4688 "tscon"

| eval Command_Check=coalesce(Process_Command_Line, CommandLine, _raw)
| regex Command_Check="(?i)tscon.*[\/-]dest\s*:"
| eval User_Creator=mvindex(Account_Name, 0)
| table _time, host, User_Creator, Command_Check

```

### ⚠️ Possibili Falsi Positivi
* Software di gestione remota IT di terze parti che si appoggiano a `tscon.exe`.
  
---

### Note di Triage / Azioni Consigliate

1. **Analisi dell'Utente (`Account_Name`)**
    Per eseguire questo attacco con successo senza conoscere la password della vittima, l'attaccante deve lanciare il comando come `NT AUTHORITY\SYSTEM`. Se l'account sorgente è `SYSTEM`, l'allarme ha una gravità critica (Severity: Critical).

2. **Correlazione degli Accessi (EventCode 4778)**
   Oltre alla riga di comando, cercare l'EventCode 4778 (Una sessione è stata ricollegata a una Window Station) nello stesso intervallo di tempo per confermare che l'hijacking ha avuto successo e determinare quale account è stato compromesso.

3. **Contenimento**
   Isolare il server bersaglio. Disconnettere forzatamente l'utente dirottato e resettare immediatamente le sue credenziali, in quanto l'attaccante potrebbe averle estratte una volta ottenuto l'accesso al desktop.
