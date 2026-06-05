# 🚨Detection of Event Log Clearing

| **Metadati** | **Dettagli** |
| :--- | :--- |
| **Tecnica MITRE ATT&CK** | `T1070.001 - Indicator Removal: Clear Windows Event Logs` |
| **Log Source** | `Windows Security (EventCode 1102) / Windows System (EventCode 104)` |

---

### Descrizione
Rileva la cancellazione manuale o scriptata dei registri degli eventi di Windows (Security o System). Gli attaccanti utilizzano questa tecnica, nota come "Terra Bruciata", nelle fasi finali di un'intrusione per eliminare le tracce delle loro attività (come creazioni di utenti, movimenti laterali o esecuzione di comandi), rendendo estremamente difficile per i team di Incident Response ricostruire la catena di attacco.

### Query SPL
```splunk
index=* (EventCode=1102 OR EventCode=104) "*cl*" ("*Security*" OR "*System*")
| table _time, host, EventCode, Account_Name, TaskCategory
```

### ⚠️ Possibili Falsi Positivi
* Script automatici di pulizia approvati.
* Risoluzione di problemi e/o correzione.

---

### Note di Triage / Azioni Consigliate

1. **Analisi dell'Utente (`Account_Name`)**
    Verificare immediatamente chi ha scatenato l'evento. La cancellazione dei log richiede privilegi amministrativi. Se l'utente è standard (Possibile Privilege Escalation) o se è un amministratore che agisce fuori orario, considerare l'evento come **Allarme Critico**.

2. **Ricerca del Metodo di Cancellazione**
   Cercare nei log precedenti (EventCode 4688 o Sysmon 1) l'uso di comandi come `wevtutil cl`, `Remove-EventLog` (PowerShell) o `Clear-EventLog` nelle finestre temporali adiacenti

3. **Contenimento**
   Isolare immediatamente l'endpoint interessato. Considerare l'host come gravemente compromesso. Avviare le procedure di Incident Response e iniziare il triage forense sui log di rete, poiché i log locali non sono più affidabili.


