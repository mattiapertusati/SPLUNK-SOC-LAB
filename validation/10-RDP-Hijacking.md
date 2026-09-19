## Validation Report: RDP Session Hijacking

**Kill Chain Phase:** Lateral Movement
**MITRE ATT&CK Technique:** [T1563.002 - Remote Services: Remote Desktop Protocol](https://attack.mitre.org/techniques/T1563/002/)

### 1. Attack Execution

* **Tool:** Atomic Red Team
* **Test Performed:** Test 1 - RDP Hijacking
* **Command Executed:**

  ```powershell
  Invoke-AtomicTest T1563.002 -TestNumbers 1 -PathToAtomicsFolder "C:\AtomicRedTeam\atomics"
  ```

<img width="715" height="193" alt="Screenshot 2026-06-11 114722" src="https://github.com/user-attachments/assets/fe9b9a1a-83c5-4530-8f5d-e217a75a93cd" />

### 2. Telemetry & Logs

* **Data Source:** Windows Security Event Log
* **Expected EventID:** 4688 (A new process has been created)

<img width="892" height="1293" alt="Screenshot 2026-06-11 114743" src="https://github.com/user-attachments/assets/eded04a5-580b-452e-8e9a-316356b13360" />

### 3. Detection & Validation

* **Rule Name:** RDP Hijacking via Tscon
* **Test Result:** Triggered = YES
* **False Positives:** Low. The use of `tscon.exe` with the `dest` parameter from the command line is uncommon during normal operations and is often associated with attempts to hijack an RDP session, especially when executed as SYSTEM.

### Splunk (SPL)

```spl id="r2k6v9"
index=wineventlog EventCode=4688 "tscon"
| eval Command_Check=coalesce(Process_Command_Line, CommandLine, _raw)
| regex Command_Check="(?i)tscon.*[\/\-]dest\s*:"
| eval User_Creator=mvindex(Account_Name, 0)
| table _time, host, User_Creator, Command_Check
```

### Microsoft Sentinel (KQL)

```kql id="t5n8q3"
SecurityEvent
| where EventID == 4688 and ProcessCommandLine has "tscon"
| extend Command_Check = coalesce(ProcessCommandLine, CommandLine, Activity)
| where Command_Check matches regex @"(?i)tscon.*[\/\-]dest\s*:"
| extend User_Creator = Account
| project TimeGenerated, Computer, User_Creator, Command_Check
```

### Sigma Rule (Agnostic)

See the **rdp_hijacking.yml** file in the repository for the complete rule.

### 4. Validation Results

1. **Attack Executed:** YES
2. **Logs Generated:** YES
3. **Detection Triggered:** YES
4. **False Positives:** Low.

<img width="1184" height="471" alt="Screenshot 2026-06-11 114753" src="https://github.com/user-attachments/assets/9962809b-ccac-4ecf-ad4a-5fb80c619dfa" />
