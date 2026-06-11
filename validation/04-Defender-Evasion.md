## 🧪 Validation Report: Windows Defender Evasion 

### 1. Attack Execution
* **Strumento:** Powershell
* **Test Eseguito:** Windows Defender Evasion 
* **Comando Lanciato:**
  
  ```powershell
  Set-MpPreference -DisableRealtimeMonitoring $true
  ```

<img width="525" height="53" alt="Screenshot 2026-06-11 112946" src="https://github.com/user-attachments/assets/d8894619-c80d-4947-9c39-d20063e54012" />

### 2. Telemetry & Logs

* Sorgente Dati: Microsoft-Windows-PowerShell/Operational
* EventID Attesi: 4103/4104
  
<img width="893" height="1210" alt="Screenshot 2026-06-11 114055" src="https://github.com/user-attachments/assets/8c1a7f12-ff16-4709-9933-2d35edd28cd7" />

### 3. Detection & Validation

* Nome Regola: Windows Defender Evasion  via PowerShell
* Risultato Test: ✅ Triggered = YES
* Falsi Positivi: NO
  
### 🔴 Splunk (SPL)

```spl
index=wineventlog source="*PowerShell*" (EventCode=4103 OR EventCode=4104) "Set-MpPreference"


| eval Script_Content=coalesce(Message, ScriptBlockText, _raw)
| regex Script_Content="(?i)-DisableR(ealtimeMonitoring)?\s+(1|\$true)"
| table _time, host, EventCode, Script_Content
```

### 🔵 Microsoft Sentinel (KQL)

```kql
PowerShellEvent
| where EventID in (4103, 4104) and ScriptBlockText has "Set-MpPreference"
| extend Script_Content = coalesce(RenderedDescription, ScriptBlockText, EventData)

| where Script_Content matches regex @"(?i)-DisableR(ealtimeMonitoring)?\s+(1|\$true)"
| project TimeGenerated, Computer, EventID, Script_Content
```

### 🟡 Sigma Rule (Agnostic)

Vedi il file **windows_defender_evasion.yml** nel repository per la regola completa.

### 4. Validation Results

1. **Attack Executed:** YES
2. **Logs Generated:** YES
3. **Detection Triggered:** YES
4. **False Positives:** Bassi.

<img width="1174" height="445" alt="Screenshot 2026-06-11 114202" src="https://github.com/user-attachments/assets/a8af5b78-e5d6-4af9-93c2-5f827556f2f8" />
