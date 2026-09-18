# 🚨 Detection of Encoded PowerShell Command

### Description
This rule detects the execution of PowerShell with obfuscation and Base64 encoding parameters (`-enc`, `-e`, `-encodedcommand`). Attackers and malware commonly use this technique to bypass clear-text security controls and hide malicious payloads.

## 🎯 MITRE ATT&CK
* **Tactic:** Execution (TA0002)
* **Technique:** Command and Scripting Interpreter (T1059)
* **Sub-technique:** PowerShell (T1059.001)

## 🚦 Alert Metadata
* **Severity:** High
* **Confidence:** Medium (It can generate false positives if IT administrators use legitimate obfuscated scripts)
* **Impact:** High

### SPL Query
```splunk
index=wineventlog EventCode=4688 (New_Process_Name="*powershell.exe" OR Image="*powershell.exe")

| eval Command_Line=coalesce(Process_Command_Line, CommandLine, _raw)
| regex Command_Line="(?i)[\/\-–—]e(n(c(o(d(e(d(c(o(m(m(a(n(d)? )? )? )? )? )? )? )? )? )? )? )?\b"
| eval User_Creator=mvindex(Account_Name, 0)
| table _time, host, User_Creator, New_Process_Name, Command_Line
```

### ⚠️ Possible False Positives
* Legitimate IT administration scripts.
* Third-party monitoring software that uses Base64 encoding to avoid formatting problems.

---

### Triage Notes / Recommended Actions

1. **Payload Inspection**
   Immediately examine the `Process_Command_Line` field to isolate the whole encoded string after the **-enc** flag (or similar flags).

2. **Forensic Decoding**
   Copy the obfuscated string and use **CyberChef**.

   > Remember that PowerShell naturally encodes in Base64 using text in **UTF-16LE** (or Unicode) format, not simple ASCII.
   > On CyberChef, the correct recipe is: `From Base64` → `Decode Text (UTF-16LE)`.

3. **Post-Decoding Analysis (Hunting for IoCs)**
   Once you obtain the clear text, analyze the code to look for:
   * External IP addresses or domains (potential Command and Control C2 servers).
   * Download URLs (for example: `Invoke-WebRequest`, `rundll32`).
   * Unusual file paths (for example: executions running inside `C:\Windows\Temp\`).
