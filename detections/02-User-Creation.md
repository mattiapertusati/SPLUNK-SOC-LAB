# 🚨 Detection of Local User Creation

| **Metadati** | **Dettagli** |
| :--- | :--- |
| **Tecnica MITRE ATT&CK** | `T1136.001 - Local Account` |
| **Log Source** | `Windows Security Event Log (EventCode 4720)` |

---

### Descrizione
Rileva la creazione di un nuovo account utente locale sul sistema. Gli attaccanti creano spesso account fittizi (`backdoor`) per garantirsi un accesso persistente all'infrastruttura, bypassando eventuali cambi di password dell'utente compromesso inizialmente.

### Query SPL
```splunk
index=wineventlog EventCode=4720 
| eval Creator_Account=mvindex(Account_Name, 0)
| table _time, host, Creator_Account, SAM_Account_Name
```

### ⚠️ Possibili Falsi Positivi
* Creazione di account legittimi (Onboarding).
* Creazioni di account temporanei con privilegi massimi e con data di scadenza breve per manutenzione e/o aggiornamenti urgenti.

---

### Note di Triage / Azioni Consigliate

1. **Verifica dell'Origine (Subject)**
   Analizzare il campo `SubjectUserName` per determinare chi ha generato l'account. Se l'utente non appartiene al reparto IT o se l'azione                  avviene fuori dal normale orario lavorativo, l'evento è critico.

2. **Contesto dell'Endpoint (Host)**
   Valutare la macchina target (`host`). La creazione di un account locale su un laptop aziendale standard (Endpoint) è altamente sospetta rispetto alla creazione su un Domain Controller.

3. **Caccia ad attività correlate (Escalation)**
   Cercare log successivi (es. EventCode 4732) per verificare se il nuovo account (`TargetUserName`) è stato immediatamente aggiunto a gruppi con privilegi elevati, come Administrators o Remote Desktop Users.
