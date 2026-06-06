# 🚨Detection of Malicious Firewall Rule Creation via Netsh

### Descrizione
Rileva la creazione di una nuova regola nel firewall di Windows tramite l'utility da riga di comando `netsh.exe`. Gli attaccanti utilizzano questa tecnica per aprire porte specifiche (solitamente in ingresso - Inbound) e garantire che il traffico del loro malware o la connessione verso i server Command & Control (C2) non venga bloccato dalle difese di rete locali dell'endpoint.

## 🎯 MITRE ATT&CK
* **Tactic:** Defense Evasion (TA0005)
* **Technique:** Impair Defenses (T1562)
* **Sub-technique:** Disable or Modify System Firewall (T1562.004)
  
## 🚦 Alert Metadata

* **Severity:** Medium
* **Confidence:** High
* **Impact:** Medium

(Nota: Portiamo Severity e Impact a Medium perché netsh viene usato quotidianamente da installer di software legittimi, browser e tool IT per configurare le porte. Diventa un alert ad alta priorità solo in base a cosa c'è scritto nella riga di comando o se il processo padre è anomalo).

### Query SPL
```splunk
index=sysmon OR index=wineventlog (EventCode=4688 OR EventCode=1) "netsh" "advfirewall" "allow"

| rex field=CommandLine "(?i)add\s+ru(le)?\b"
| rex field=_raw "name=\"(?<nome_regola>[^\"]+)\""
| table _time, host, EventCode, User, CommandLine, Image, nome_regola, ParentImage
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
