# Detection of Windows Defender Evasion (Real-Time Protection Disabled)

### Description
This rule detects attempts to disable Windows Defender real-time protection using the native `Set-MpPreference` Cmdlet. Attackers run this command to "turn off the cameras" before downloading or executing malicious payloads (malware, ransomware) on the endpoint, avoiding immediate blocking by the antivirus.

## MITRE ATT&CK
* **Tactic:** Defense Evasion (TA0005)
* **Technique:** Impair Defenses (T1562)
* **Sub-technique:** Disable or Modify Tools (T1562.001)

## Alert Metadata
* **Severity:** High
* **Confidence:** Medium
* **Impact:** High

### SPL Query
```splunk
index=wineventlog source="*PowerShell*" (EventCode=4103 OR EventCode=4104) "Set-MpPreference"


| eval Script_Content=coalesce(Message, ScriptBlockText, _raw)

| regex Script_Content="(?i)-DisableR(ealtimeMonitoring)?\s+(1|\$true)"
| table _time, host, EventCode, Script_Content
```

### Possible False Positives
* Legitimate interventions by IT administrators for testing or troubleshooting.
* Automation scripts that work only with the antivirus disabled.

---

### Triage Notes / Recommended Actions

1. **Context Analysis (Payload)**
   Inspect the `Message` field to confirm that the parameter passed is `$true` (or `1`), which indicates the actual intention to turn off monitoring, and not `$false` (which would reactivate it).

2. **Hunting for Related Commands**
    An attacker who uses PowerShell to turn off Defender often uses it immediately after to download malware. Look for executions of `Invoke-WebRequest` (iwr) or `Net.WebClient` within the same timeframe.
   
3. **Containment (Remediation)**
   If the action is malicious, isolate the host from the corporate network immediately. Reactivating Windows Defender must be forced via Group Policy (GPO) or through the central EDR console, as the attacker may have altered local permissions.
