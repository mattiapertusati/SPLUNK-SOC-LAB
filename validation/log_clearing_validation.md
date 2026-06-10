## 🧪 Validation Report: Clear Windows Event Logs

**Fase della Kill Chain:** Defense Evasion
**Tecnica MITRE ATT&CK:** [T1070.001 - Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001/)

### 1. Attack Execution
* **Strumento:** Native OS Command / Atomic Red Team
* **Comando Lanciato:**
  ```powershell
  wevtutil cl Security
  ```

SCREENSHOT 1

### 2. Telemetry & Logs

* **Sorgente Dati:** Windows Security Event Log
* **EventID Atteso:** 1102 (The audit log was cleared)

SCREENSHOT 2

### 3. Detection & Validation

* **Nome Regola:** Security Event Log Cleared
* **Risultato Test:** ✅ Triggered = YES
* **Falsi Positivi:** Bassi. Svuotare il log di Sicurezza è un'azione estremamente anomala che dovrebbe essere eseguita solo durante operazioni di manutenzione straordinaria e rigidamente tracciate.

### 🔴 Splunk (SPL)

```spl
index=wineventlog (EventCode=1102 OR EventCode=104)
| eval User_Responsible=coalesce(SubjectUserName, Account_Name, UserID, "SYSTEM/Unknown")
| table _time, host, EventCode, User_Responsible, TaskCategory
```  

### 🔵 Microsoft Sentinel (KQL)

```kql
SecurityEvent
| where EventID == 1102
| project TimeGenerated, Computer, Account, Activity
```

### 🟡 Sigma Rule (Agnostic)
Vedi il file **log_clearing.yml** nel repository per la regola completa.

### 4. Validation Results

* **Attack Executed:** YES
* **Logs Generated:** YES (Validato su telemetria storica)
* **Detection Triggered:** YES
* **False Positives:** Bassi.

SCREENSHOT 3
