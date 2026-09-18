## Validation Report: Encoded PowerShell

### 1. Attack Execution
* **Tool:** Atomic Red Team
* **Executed Test:** Test 1 - Mimikatz
* **Launched Command:**

  ```powershell
  Invoke-AtomicTest T1059.001 -TestNumbers 1 -PathToAtomicsFolder "C:\AtomicRedTeam\atomics"
  ```

<img width="838" height="228" alt="Screenshot 2026-06-10 223400" src="https://github.com" />

### 2. Telemetry & Logs

* Data Source: Windows Security Event Log
* Expected EventIDs: 4688 (Powershell)

<img width="903" height="728" alt="Screenshot 2026-06-10 223926" src="https://github.com" />

### 3. Detection & Validation

* Rule Name: Encoded-PowerShell via PowerShell
* Test Result: Triggered = YES
* False Positives: NO 

### Splunk (SPL)

```spl
index=wineventlog EventCode=4688 (New_Process_Name="*powershell.exe" OR Image="*powershell.exe")

| eval Command_Line=coalesce(Process_Command_Line, CommandLine, _raw)
| regex Command_Line="(?i)[\/\-–—]e(n(c(o(d(e(d(c(o(m(m(a(n(d)? )? )? )? )? )? )? )? )? )? )? )?\b"
| eval User_Creator=mvindex(Account_Name, 0)
| table _time, host, User_Creator, New_Process_Name, Command_Line
```

### Microsoft Sentinel (KQL)

```kql
SecurityEvent
| where EventID == 4688 and (NewProcessName endswith "powershell.exe" or Process endswith "powershell.exe")
| extend Command_Line = coalesce(ProcessCommandLine, CommandLine, Activity)
| where Command_Line matches regex @"(?i)[\/\-–—]e(n(c(o(d(e(d(c(o(m(m(a(n(d)? )? )? )? )? )? )? )? )? )? )? )?\b"
| extend User_Creator = Account
| project TimeGenerated, Computer, User_Creator, NewProcessName, Command_Line
```

### Sigma Rule (Agnostic)

See the **encoded_powershell_command.yml** file in the repository for the complete rule.

### 4. Validation Results

1. **Attack Executed:** YES
2. **Logs Generated:** YES
3. **Detection Triggered:** YES
4. **False Positives:** Low.

<img width="1193" height="658" alt="Screenshot 2026-06-10 223940" src="https://github.com" />
