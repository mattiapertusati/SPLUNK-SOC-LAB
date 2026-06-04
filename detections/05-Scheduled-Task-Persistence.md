# 🚨 Detection of Scheduled Task Creation for Persistence

| **Metadati** | **Dettagli** |
| :--- | :--- |
| **Tecnica MITRE ATT&CK** | `T1053.005 - Scheduled Task/Job: Scheduled Task` |
| **Log Source** | `Windows Security Event Log (EventCode 4698)` |

---

### Descrizione
Rileva la creazione di una nuova attività pianificata (Scheduled Task) sul sistema. Questa tecnica viene sfruttata regolarmente dagli attaccanti per garantire la persistenza all'interno dell'infrastruttura, consentendo al malware o alle backdoor di eseguirsi automaticamente a intervalli prestabiliti o al riavvio del computer, anche in caso di rimozione dell'accesso iniziale.

### Query SPL
```splunk
index=wineventlog EventCode=4698
| rex field=_raw "<Command>(?<Task_Command>[^<]+)</Command>"
| table _time, host, Account_Name, Task_Name, Task_Command
```

### ⚠️ Possibili Falsi Positivi
* Installazione o aggiornamenti che richiedono una pianificazione.
* Script di manutenzione e/o controllo che richiedono una ripetizione (pianificazione).

---

### Note di Triage / Azioni Consigliate

1. **Analisi del Percorso dell'Eseguibile ('Task_Command')**
Ispezionare attentamente il percorso del file avviato dalla task. L'esecuzione di binari posizionati in cartelle temporanee o scrivibili dagli utenti (es. 'C:\Windows\Temp\', 'C:\Users\...\AppData\') è un fortissimo indicatore di attività malevola.

2. **Verifica del Nome della Task ('Task_Name')**
Gli attaccanti usano spesso tecniche di Masquerading nominando le attività in modo simile a servizi critici di Windows (es. 'Windows_Update_Helper', 'MfeSysFlt'). Confrontare il nome con la documentazione interna e verificare la presenza di anomalie nei caratteri o nel path.   

3. **Investigazione dell'Autore (Account_Name)**
   Verificare se l'account che ha generato l'attività ha l'autorizzazione per farlo. Se l'azione non corrisponde a una finestra di manutenzione o a un ticket approvato, procedere con l'isolamento dell'host per contenimento.
