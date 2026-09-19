## Validation Report: Firewall Manipulation

**Kill Chain Phase:** Defense Evasion
**MITRE ATT&CK Technique:** [T1562.004 - Impair Defenses: Disable or Modify System Firewall](https://attack.mitre.org/techniques/T1562/004/)

### 1. Attack Execution

* **Tool:** Native OS Command
* **Test Performed:** Disable Windows Firewall / Add Allow Rule via Netsh
* **Command Executed:**

  ```powershell
  netsh advfirewall set allprofiles state off
  ```

<img width="480" height="90" alt="Screenshot 2026-06-11 114524" src="https://github.com/user-attachments/assets/5aa53e83-ae3f-48aa-a36d-e2cc8dd83b7a" />

### 2. Telemetry & Logs

* **Data Source:** Sysmon / Windows Security Event Log
* **Expected EventID:** 1 (Sysmon - Process Creation) and 4688 (Security - Process Creation)

<img width="905" height="1200" alt="Screenshot 2026-06-11 114634" src="https://github.com/user-attachments/assets/c66f3409-b042-43a2-8e08-adbbafba03cd" />

### 3. Detection & Validation

* **Rule Name:** Netsh Firewall Manipulation
* **Test Result:** Triggered = YES
* **False Positives:** Low. Command-line firewall modifications (`netsh`) are generally automated through GPO in enterprise environments. Manual changes, especially when they open unusual ports (e.g., 4444) or disable entire firewall profiles, are highly suspicious.

### Splunk (SPL)

```spl id="n3q6t8"
index=sysmon OR index=wineventlog (EventCode=4688 OR EventCode=1) "netsh" "advfirewall" "allow"
| rex field=_raw "name=\"(?<nome_regola>[^\"]+)\""
| table _time, host, EventCode, User, CommandLine, Image, nome_regola, ParentImage
```

### Microsoft Sentinel (KQL)

```kql id="p5w9x3"
DeviceProcessEvents
| where FileName =~ "netsh.exe" and ProcessCommandLine has "advfirewall" and ProcessCommandLine has "allow"
| extend nome_regola = extract(@"name=""([^""]+)""", 1, ProcessCommandLine)
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, nome_regola, InitiatingProcessFileName
```

### Sigma Rule (Agnostic)

See the **firewall_manipulation.yml** file in the repository for the complete rule.

### 4. Validation Results

1. **Attack Executed:** YES
2. **Logs Generated:** YES
3. **Detection Triggered:** YES
4. **False Positives:** Low.

<img width="1176" height="506" alt="Screenshot 2026-06-11 114651" src="https://github.com/user-attachments/assets/82d93450-ccde-47b5-95d2-a2d08e287e0c" />
