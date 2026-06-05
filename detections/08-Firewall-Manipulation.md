# 🚨Detection of Malicious Firewall Rule Creation via Netsh

| **Metadati** | **Dettagli** |
| :--- | :--- |
| **Tecnica MITRE ATT&CK** | `T1562.004 - Impair Defenses: Disable or Modify System Firewall` |
| **Log Source** | `Sysmon (EventID 1) / Windows Security (EventCode 4688)` |

---

### Descrizione
Rileva la creazione di una nuova regola nel firewall di Windows tramite l'utility da riga di comando `netsh.exe`. Gli attaccanti utilizzano questa tecnica per aprire porte specifiche (solitamente in ingresso - Inbound) e garantire che il traffico del loro malware o la connessione verso i server Command & Control (C2) non venga bloccato dalle difese di rete locali dell'endpoint.

### Query SPL
```splunk
index=* (EventCode=4688 OR EventCode=1) "*netsh*" "*add rule*" "*allow*"
| rex field=_raw "name=\"(?<nome_regola>[^\"]+)\""
| eval New_Account_Name=mvindex(Account_Name, 0)
| table _time, host, EventCode, New_Account_Name, CommandLine, Image, nome_regola, Creator_Process_Name
```

### ⚠️ Possibili Falsi Positivi
* Installazione di nuovi software legittimi che richiedono l'apertura di porte.
* Script di configurazione di rete automatizzati.

---

### Note di Triage / Azioni Consigliate

1. **Analisi della Porta e del Protocollo (`CommandLine`)**
   Controllare quale porta è stata aperta. Porte come `4444` (Metasploit), `443` (spesso mascherata come traffico web) o porte ad alto numero insolite richiedono indagini immediate.

2. **Verifica del Nome della Regola (`name=...`)**
   Valutare l'uso di tecniche di Masquerading. Gli attaccanti spesso nominano le regole come "Core_Update", "Windows Defender Service" o simili per eludere ispezioni visive rapide.

3. **Identificazione del Processo Genitore**
   Se si utilizzano i log di Sysmon, verificare quale processo ha generato `netsh.exe`. Se avviato da `cmd.exe` o `powershell.exe` in contesti anomali, la probabilità di attacco è molto alta.

4. **Contenimento (Remediation)**
   Isolare la macchina ed eliminare tempestivamente la regola malevola dal firewall tramite GPO o connessione remota sicura.
