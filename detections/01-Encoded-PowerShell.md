# 🚨 Detection of Encoded PowerShell Command


| 🏷️ **Metadati** | 📋 **Dettagli** |
| :--- | :--- |
| **Tecnica MITRE ATT&CK** | 💻 `T1059.001 - PowerShell` |
| **Log Source** | 🪵 `Windows Security Event Log (EventCode 4688)` |

---

### 📝 Descrizione
Rileva l'esecuzione di PowerShell con parametri di offuscamento e codifica in Base64 (`-enc`, `-e`, `-encodedcommand`). Questa tecnica è comunemente usata da malware e attaccanti per bypassare i controlli in chiaro e nascondere payload maligni.

### 🔍 Query SPL
```splunk
index=wineventlog EventCode=4688 New_Process_Name="*powershell.exe" (Process_Command_Line="* -enc*" OR Process_Command_Line="* -e *" OR Process_Command_Line="* -encoded*")
| table _time, host, Account_Name, New_Process_Name, Process_Command_Line
```

### ⚠️ Possibili Falsi Positivi
* Script di amministrazione IT legittimi.
* Software di monitoraggio di terze parti che utilizzano la codifica Base64 per evitare problemi di formattazione.

---

### 🛠️ Note di Triage / Azioni Consigliate

1. **Ispezione del Payload**
   Esaminare immediatamente il campo `Process_Command_Line` per isolare l'intera stringa codificata dopo il flag **-enc** (o simili).

2. **Decodifica Forense**
   Copiare la stringa offuscata e utilizzare **CyberChef**.

   > Ricorda che PowerShell codifica nativamente in Base64 partendo da testo in formato **UTF-16LE** (o Unicode), non semplice ASCII.
   > Su CyberChef la ricetta corretta è: `From Base64` ➡️ `Decode Text (UTF-16LE)`.

3. **Analisi post-decodifica (Caccia agli IoC)**
   Una volta ottenuto il testo in chiaro, analizzare il codice alla ricerca di:
   * 🌐 Indirizzi IP esterni o domini (potenziali server di Comando e Controllo C2).
   * 📥 URL di download (es. `Invoke-WebRequest`, `rundll32`).
   * 📁 Percorsi di file anomali (es. esecuzioni spostate dentro `C:\Windows\Temp\`).
