# 🚨 Detection of Lateral Movement via PsExec

| **Metadati** | **Dettagli** |
| :--- | :--- |
| **Tecnica MITRE ATT&CK** | `T1569.002 - System Services: Service Execution  +  T1021.002 - Remote Services: SMB/Windows Admin Shares` |
| **Log Source** | `Windows System (EventCode 7045) / Security (EventCode 4697)` |

---

### Descrizione
Rileva l'installazione di un nuovo servizio di sistema associato a PsExec, una utility legittima della suite Sysinternals di Microsoft. Sebbene nata per scopi di amministrazione IT, PsExec è ampiamente abusata dagli attaccanti (inclusi i gruppi Ransomware) per eseguire comandi o distribuire payload su macchine remote all'interno del dominio. L'esecuzione di PsExec da remoto comporta la scrittura del binario `PSEXESVC.exe` nella share `ADMIN$` e la successiva creazione del servizio omonimo per l'esecuzione con privilegi di SYSTEM.

### Query SPL
```splunk
index=wineventlog (EventCode=7045 OR EventCode=4697) "*PSEXESVC*"
| table _time, host, EventCode, Account_Name, Service_Name, Service_File_Name
```

### ⚠️ Possibili Falsi Positivi
* Utilizzo legittimo di PsExec da parte di amministratori di sistema.
* Scansioni di vulnerabilità autorizzate che utilizzano PsExec.

---

### Note di Triage / Azioni Consigliate

1. **Verifica dell'Utente (`Account_Name`)**
   Controllare quale account ha installato il servizio. Se l'account appartiene a un utente standard (che non dovrebbe avere privilegi di amministrazione remota) o se l'azione avviene al di fuori dei normali orari lavorativi, l'allarme è da considerarsi critico.

2. **Analisi del Binario (`Service_File_Name`)**
   Sebbene il nome di default sia `PSEXESVC.exe`, gli attaccanti possono rinominare il servizio (usando l'opzione `-r` di PsExec). Prestare attenzione a servizi con nomi casuali (es. `x7gf9.exe`) installati nella directory `C:\Windows\`.   

3. **Caccia Correlata (Log di Rete)**
   Cercare connessioni in ingresso sulla porta 445 (SMB) verso l'host compromesso nello stesso intervallo temporale per identificare la macchina sorgente da cui è partito l'attacco (il "Paziente Zero").

4. **Contenimento**
   Isolare l'host bersaglio e l'host sorgente. Revocare immediatamente le credenziali dell'account compromesso utilizzato per il movimento laterale.
