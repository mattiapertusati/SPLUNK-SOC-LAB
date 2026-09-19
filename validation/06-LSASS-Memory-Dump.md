## Validation Report: LSASS Memory Dump

**Kill Chain Phase:** Credential Access
**MITRE ATT&CK Technique:** [T1003.001 - OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)

### 1. Attack Execution

* **Tool:** Atomic Red Team
* **Test Performed:** Test 2 - Dump LSASS.exe using comsvcs.dll
* **Command Executed:**

  ```powershell
  Invoke-AtomicTest T1003.001 -TestNumbers 2 -PathToAtomicsFolder "C:\AtomicRedTeam\atomics"
  ```

<img width="1259" height="762" alt="Screenshot 2026-06-09 172303" src="https://github.com/user-attachments/assets/5c61bde9-679d-41a1-a38f-3e29ea1fec3c" />

### 2. Telemetry & Logs

* **Data Source:** Sysmon / PowerShell Operational
* **Expected EventID:** 1 (Sysmon) or 4104 (PowerShell)

<img width="956" height="1176" alt="Screenshot 2026-06-09 220145" src="https://github.com/user-attachments/assets/5d7941f9-78fa-43b6-a57b-049ff151627e" />

### 3. Detection & Validation

* **Rule Name:** LSASS Memory Dump via PowerShell
* **Test Result:** Triggered = YES
* **False Positives:** NO (The rule is strictly associated with comsvcs.dll)

### Splunk (SPL)

```spl id="y4t7n2"
index=sysmon EventCode=1 "comsvcs.dll" ("MiniDump" OR "#24")
| table _time, host, User, CommandLine
```

### Microsoft Sentinel (KQL)

```kql id="h2k8m5"
DeviceProcessEvents
| where FileName =~ "rundll32.exe"
| where ProcessCommandLine has "comsvcs.dll" and (ProcessCommandLine has "MiniDump" or ProcessCommandLine has "#24")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
```

### Sigma Rule (Agnostic)

See the **lsass_memory_dump.yml** file in the repository for the complete rule.

### 4. Validation Results

1. **Attack Executed:** YES
2. **Logs Generated:** YES
3. **Detection Triggered:** YES
4. **False Positives:** Low. The use of comsvcs.dll combined with MiniDump from the command line is highly unusual for normal system administration activities and is generally indicative of malicious activity or an authorized security test.

<img width="1209" height="381" alt="Screenshot 2026-06-09 220159" src="https://github.com/user-attachments/assets/52a65241-c0aa-464a-8ae5-b6ee0be4ee73" />
