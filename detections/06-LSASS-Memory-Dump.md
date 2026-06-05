# 🚨 Detection of LSASS Memory Dumping via Comsvcs.dll

| **Metadati** | **Dettagli** |
| :--- | :--- |
| **Tecnica MITRE ATT&CK** | `T1003.001 - OS Credential Dumping: LSASS Memory` |
| **Log Source** | `Sysmon (EventID 1) / Windows Security (EventCode 4688)` |

---

### Descrizione
Rileva il tentativo di estrarre le credenziali in chiaro e gli hash delle password dalla memoria del processo di sistema `LSASS` (Local Security Authority Subsystem Service). L'attacco utilizza una tecnica "Living off the Land", sfruttando il binario legittimo di Windows `rundll32.exe` per richiamare la funzione esportata MiniDump all'interno della libreria di sistema `comsvcs.dll`. Questo permette all'attaccante di aggirare le restrizioni di base e salvare un file di dump (solitamente `.dmp`) per l'estrazione offline delle password tramite tool come Mimikatz.

### Query SPL

```splunk
index=sysmon EventCode=1 "comsvcs.dll" "MiniDump"
| table _time, host, CommandLine
```

### ⚠️ Possibili Falsi Positivi
* Presenza di EDR/Antivirus che effettuano dump di memoria per analisi.
* Presenza di dump per risoluzione di problemi e/o crash di sistema.

---

### Note di Triage / Azioni Consigliate

1. **Analisi della Riga di Comando ('CommandLine')**
   Verificare il percorso in cui viene salvato il file di dump. Se il file viene scritto in directory temporanee (es. 'C:\Windows\Temp\', 'C:\Users\...\AppData\Local\Temp\'), l'attività è quasi certamente malevola.

2. **Caccia a comandi correlati**
   Un attaccante che usa PowerShell per spegnere Defender, spesso lo usa subito dopo per scaricare il malware. Cercare nello stesso intervallo temporale esecuzioni di 'Invoke-WebRequest' (iwr) o 'Net.WebClient'.
   
3. **Contenimento (Remediation)**
   Se l'azione è malevola, isolare immediatamente l'host dalla rete aziendale. La riattivazione di Windows Defender dovrà essere forzata tramite Group Policy (GPO) o tramite la console EDR centrale, poiché l'attaccante potrebbe aver alterato i permessi locali.
