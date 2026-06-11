## 🧪 Validation Report: Firewall Manipulation

**Fase della Kill Chain:** Defense Evasion
**Tecnica MITRE ATT&CK:** [T1562.004 - Impair Defenses: Disable or Modify System Firewall](https://attack.mitre.org/techniques/T1562/004/)

### 1. Attack Execution
* **Strumento:** Native OS Command
* **Test Eseguito:** Disable Windows Firewall / Add Allow Rule via Netsh
* **Comando Lanciato:**
  ```powershell
  netsh advfirewall set allprofiles state off
  ```
<img width="480" height="90" alt="Screenshot 2026-06-11 114524" src="https://github.com/user-attachments/assets/5aa53e83-ae3f-48aa-a36d-e2cc8dd83b7a" />

### 2. Telemetry & Logs

* **Sorgente Dati:** Sysmon / Windows Security Event Log
* **EventID Atteso:** 1 (Sysmon - Process Creation) e 4688 (Security - Process Creation)

<img width="905" height="1200" alt="Screenshot 2026-06-11 114634" src="https://github.com/user-attachments/assets/c66f3409-b042-43a2-8e08-adbbafba03cd" />

### 3. Detection & Validation

* **Nome Regola:** Netsh Firewall Manipulation
* **Risultato Test:** ✅ Triggered = YES
* **Falsi Positivi:** Bassi. Le modifiche al firewall da riga di comando (`netsh`) sono generalmente automatizzate tramite GPO in ambienti enterprise. Modifiche manuali, specialmente se aprono porte anomale (es. 4444) o spengono interi profili, sono altamente sospette.

### 🔴 Splunk (SPL)
```spl
index=sysmon OR index=wineventlog (EventCode=4688 OR EventCode=1) "netsh" "advfirewall" "allow"
| rex field=_raw "name=\"(?<nome_regola>[^\"]+)\""
| table _time, host, EventCode, User, CommandLine, Image, nome_regola, ParentImage
```

### 🔵 Microsoft Sentinel (KQL)
```kql
DeviceProcessEvents
| where FileName =~ "netsh.exe" and ProcessCommandLine has "advfirewall" and ProcessCommandLine has "allow"
| extend nome_regola = extract(@"name=""([^""]+)""", 1, ProcessCommandLine)
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, nome_regola, InitiatingProcessFileName
```

### 🟡 Sigma Rule (Agnostic)
Vedi il file **firewall_manipulation.yml** nel repository per la regola completa.

### 4. Validation Results

1. **Attack Executed:** YES
2. **Logs Generated:** YES
3. **Detection Triggered:** YES
4. **False Positives:** Bassi.

<img width="1176" height="506" alt="Screenshot 2026-06-11 114651" src="https://github.com/user-attachments/assets/82d93450-ccde-47b5-95d2-a2d08e287e0c" />

