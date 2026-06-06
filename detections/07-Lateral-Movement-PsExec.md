# 🚨 Detection of Lateral Movement via PsExec

### Descrizione
Rileva l'installazione di un nuovo servizio di sistema associato a PsExec, una utility legittima della suite Sysinternals di Microsoft. Sebbene nata per scopi di amministrazione IT, PsExec è ampiamente abusata dagli attaccanti (inclusi i gruppi Ransomware) per eseguire comandi o distribuire payload su macchine remote all'interno del dominio. L'esecuzione di PsExec da remoto comporta la scrittura del binario `PSEXESVC.exe` nella share `ADMIN$` e la successiva creazione del servizio omonimo per l'esecuzione con privilegi di SYSTEM.

## 🎯 MITRE ATT&CK
* **Tactic:** Lateral Movement (TA0008), Execution (TA0002)
* **Technique:** Services (T1021) o Command and Scripting Interpreter (T1059)
* **Sub-technique:** SMB/Windows Admin Shares (T1021.002)
  
## 🚦 Alert Metadata

* **Severity:** High
* **Confidence:** High
* **Impact:** High

(Nota: Portiamo la Severity a High invece di Critical solo perché PsExec è uno strumento ufficiale Microsoft usato massicciamente dagli amministratori IT. Diventa Critical nel momento in cui il triage conferma che l'utente non è un admin o il nome del file è alterato).

### Query SPL
```splunk
index=wineventlog (EventCode=7045 OR EventCode=4697) ("*PSEXESVC*" OR "*PsExec execution service*")
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
