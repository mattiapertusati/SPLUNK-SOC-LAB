# 🚨Detection of Event Log Clearing

### Descrizione
Rileva la cancellazione manuale o scriptata dei registri degli eventi di Windows (Security o System). Gli attaccanti utilizzano questa tecnica, nota come "Terra Bruciata", nelle fasi finali di un'intrusione per eliminare le tracce delle loro attività (come creazioni di utenti, movimenti laterali o esecuzione di comandi), rendendo estremamente difficile per i team di Incident Response ricostruire la catena di attacco.

## 🎯 MITRE ATT&CK
* **Tactic:** Defense Evasion (TA0005)
* **Technique:** Indicator Removal (T1070)
* **Sub-technique:** Clear Windows Event Logs (T1070.001)

## 🚦 Alert Metadata
* **Severity:** Critical
* **Confidence:** High
* **Impact:** High

(Nota: La Severity è Critical perché non esistono motivi di business o di amministrazione IT ordinaria per cancellare l'intero log di Sicurezza o di Sistema. Quando questo accade, è quasi sempre un attacco o un amministratore che sta cercando di nascondere un errore grave).

### Query SPL
```splunk
index=wineventlog (EventCode=1102 OR EventCode=104)
| eval User_Responsible=coalesce(SubjectUserName, Account_Name, UserID, "SYSTEM/Unknown")
| table _time, host, EventCode, User_Responsible, TaskCategory
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


