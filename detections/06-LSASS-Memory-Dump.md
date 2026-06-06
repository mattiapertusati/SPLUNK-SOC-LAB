# 🚨 Detection of LSASS Memory Dumping via Comsvcs.dll

### Descrizione
Rileva il tentativo di estrarre le credenziali in chiaro e gli hash delle password dalla memoria del processo di sistema `LSASS` (Local Security Authority Subsystem Service). L'attacco utilizza una tecnica "Living off the Land", sfruttando il binario legittimo di Windows `rundll32.exe` per richiamare la funzione esportata MiniDump all'interno della libreria di sistema `comsvcs.dll`. Questo permette all'attaccante di aggirare le restrizioni di base e salvare un file di dump (solitamente `.dmp`) per l'estrazione offline delle password tramite tool come Mimikatz.

## 🎯 MITRE ATT&CK
* **Tactic:** Credential Access (TA0006)
* **Technique:** OS Credential Dumping (T1003)
* **Sub-technique:** LSASS Memory (T1003.001)
* 
## 🚦 Alert Metadata

⚠️ Nota sulla Severity: Il dumping di LSASS è uno dei segnali più gravi in assoluto in una rete aziendale (spesso precede il ransomware). Se ha successo, l'attaccante ha le chiavi del regno. Per questo la Severity va alzata al massimo.

* **Severity:** Critical
* **Confidence:** High
* **Impact:** Critical

### Query SPL

```splunk
index=sysmon EventCode=1 "comsvcs.dll" ("MiniDump" OR "#24")
| table _time, host, User, CommandLine
```

### ⚠️ Possibili Falsi Positivi
* Presenza di EDR/Antivirus che effettuano dump di memoria per analisi.
* Presenza di dump per risoluzione di problemi e/o crash di sistema.

---

### Note di Triage / Azioni Consigliate

1. **Analisi della Riga di Comando (`CommandLine`)**
   Verificare il percorso in cui viene salvato il file di dump. Se il file viene scritto in directory temporanee (es. `C:\Windows\Temp\`, `C:\Users\...\AppData\Local\Temp\`), l'attività è quasi certamente malevola.

2. **Verifica dei Privilegi**
   Questo attacco richiede privilegi di Amministratore (nello specifico `SeDebugPrivilege`). Investigare immediatamente quale account ha lanciato il comando: se è un account utente standard compromesso che ha effettuato una `Privilege Escalation`, o se è un account amministrativo legittimo di cui sono state rubate le credenziali.
   
3. **Contenimento (Remediation)**
   Considerare l'host come criticamente compromesso. Isolare immediatamente la macchina dalla rete. Poiché l'attaccante potrebbe aver già estratto e decifrato le password, è obbligatorio forzare il reset delle credenziali per tutti gli account che hanno effettuato l'accesso di recente su quell'endpoint.
