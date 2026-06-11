## 🧪 Validation Report: RDP Session Hijacking

**Fase della Kill Chain:** Lateral Movement
**Tecnica MITRE ATT&CK:** [T1563.002 - Remote Services: Remote Desktop Protocol](https://attack.mitre.org/techniques/T1563/002/)

### 1. Attack Execution
* **Strumento:** Atomic Red Team
* **Test Eseguito:** Test 1 - RDP Hijacking
* **Comando Lanciato:**
  ```powershell
  Invoke-AtomicTest T1563.002 -TestNumbers 1 -PathToAtomicsFolder "C:\AtomicRedTeam\atomics"
  ```
  
<img width="715" height="193" alt="Screenshot 2026-06-11 114722" src="https://github.com/user-attachments/assets/fe9b9a1a-83c5-4530-8f5d-e217a75a93cd" />

### 2. Telemetry & Logs

* **Sorgente Dati:** Windows Security Event Log
* **EventID Atteso:** 4688 (A new process has been created)

<img width="892" height="1293" alt="Screenshot 2026-06-11 114743" src="https://github.com/user-attachments/assets/eded04a5-580b-452e-8e9a-316356b13360" />

### 3. Detection & Validation

* **Nome Regola:** RDP Hijacking via Tscon
* **Risultato Test:** ✅ Triggered = YES
* **Falsi Positivi:** Bassi. L'utilizzo di `tscon.exe` con il parametro `dest` da linea di comando è raro nelle normali operazioni e quasi sempre riconducibile a tentativi di furto di sessione RDP (spesso eseguiti come SYSTEM).

### 🔴 Splunk (SPL)
```spl
index=wineventlog EventCode=4688 "tscon"
| eval Command_Check=coalesce(Process_Command_Line, CommandLine, _raw)
| regex Command_Check="(?i)tscon.*[\/\-]dest\s*:"
| eval User_Creator=mvindex(Account_Name, 0)
| table _time, host, User_Creator, Command_Check
```

### 🔵 Microsoft Sentinel (KQL)
```kql
SecurityEvent
| where EventID == 4688 and ProcessCommandLine has "tscon"
| extend Command_Check = coalesce(ProcessCommandLine, CommandLine, Activity)
| where Command_Check matches regex @"(?i)tscon.*[\/\-]dest\s*:"
| extend User_Creator = Account
| project TimeGenerated, Computer, User_Creator, Command_Check
```

### 🟡 Sigma Rule (Agnostic)
Vedi il file **rdp_hijacking.yml** nel repository per la regola completa.

### 4. Validation Results

1. **Attack Executed:** YES
2. **Logs Generated:** YES
3. **Detection Triggered:** YES
4. **False Positives:** Bassi.

<img width="1184" height="471" alt="Screenshot 2026-06-11 114753" src="https://github.com/user-attachments/assets/9962809b-ccac-4ecf-ad4a-5fb80c619dfa" />

