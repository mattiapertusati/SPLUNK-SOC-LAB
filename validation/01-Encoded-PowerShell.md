## 🧪 Validation Report: Encoded PowerShell

### 1. Attack Execution
* **Strumento:** Atomic Red Team
* **Test Eseguito:** Test 1 - Mimikatz
* **Comando Lanciato:**

  ```powershell
  Invoke-AtomicTest T1059.001 -TestNumbers 1 -PathToAtomicsFolder "C:\AtomicRedTeam\atomics"
  ```

<img width="838" height="228" alt="Screenshot 2026-06-10 223400" src="https://github.com/user-attachments/assets/fae8e2a3-9d33-4947-8169-ccbca1da2cf0" />

### 2. Telemetry & Logs

* Sorgente Dati: Windows Security Event Log
* EventID Attesi: 4688 (Powershell)

<img width="903" height="728" alt="Screenshot 2026-06-10 223926" src="https://github.com/user-attachments/assets/1deb1c42-4d37-4d49-b23e-d062b8f8986a" />

### 3. Detection & Validation

* Nome Regola: Encoded-PowerShell via PowerShell
* Risultato Test: ✅ Triggered = YES
* Falsi Positivi: NO 

### 🔴 Splunk (SPL)

```spl
index=wineventlog EventCode=4688 (New_Process_Name="*powershell.exe" OR Image="*powershell.exe")

| eval Command_Line=coalesce(Process_Command_Line, CommandLine, _raw)
| regex Command_Line="(?i)[\/\-–—]e(n(c(o(d(e(d(c(o(m(m(a(n(d)? )? )? )? )? )? )? )? )? )? )? )?\b"
| eval User_Creator=mvindex(Account_Name, 0)
| table _time, host, User_Creator, New_Process_Name, Command_Line
```

### 🔵 Microsoft Sentinel (KQL)

```kql
SecurityEvent
| where EventID == 4688 and (NewProcessName endswith "powershell.exe" or Process endswith "powershell.exe")
| extend Command_Line = coalesce(ProcessCommandLine, CommandLine, Activity)
| where Command_Line matches regex @"(?i)[\/\-–—]e(n(c(o(d(e(d(c(o(m(m(a(n(d)? )? )? )? )? )? )? )? )? )? )? )?\b"
| extend User_Creator = Account
| project TimeGenerated, Computer, User_Creator, NewProcessName, Command_Line
```

### 🟡 Sigma Rule (Agnostic)

Vedi il file **encoded_powershell_command.yml** nel repository per la regola completa.

### 4. Validation Results

1. **Attack Executed:** YES
2. **Logs Generated:** YES
3. **Detection Triggered:** YES
4. **False Positives:** Bassi.

<img width="1193" height="658" alt="Screenshot 2026-06-10 223940" src="https://github.com/user-attachments/assets/7d838e05-725e-496d-8430-68ad264f0536" />
