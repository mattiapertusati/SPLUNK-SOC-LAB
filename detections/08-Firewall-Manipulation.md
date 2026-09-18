# Detection of Malicious Firewall Rule Creation via Netsh

### Description
This rule detects the creation of a new Windows firewall rule using the `netsh.exe` command-line utility. Attackers use this technique to open specific ports (usually inbound) and ensure that their malware traffic or connection to Command & Control (C2) servers is not blocked by the endpoint's local network defenses.

## MITRE ATT&CK
* **Tactic:** Defense Evasion (TA0005)
* **Technique:** Impair Defenses (T1562)
* **Sub-technique:** Disable or Modify System Firewall (T1562.004)
  
## Alert Metadata

* **Severity:** Medium
* **Confidence:** High
* **Impact:** Medium

(Note: Severity and Impact are set to Medium because netsh is used daily by legitimate software installers, browsers, and IT tools to configure ports. It becomes a high-priority alert only based on the command-line content or if the parent process is unusual).

### SPL Query
```splunk
index=sysmon OR index=wineventlog (EventCode=4688 OR EventCode=1) "netsh" "advfirewall" "allow"

| rex field=CommandLine "(?i)add\s+ru(le)?\b"
| rex field=_raw "name=\"(?<nome_regola>[^\"]+)\""
| table _time, host, EventCode, User, CommandLine, Image, nome_regola, ParentImage
```

### Possible False Positives
* Installation of new legitimate software that requires opening ports.
* Automated network configuration scripts.

---

### Triage Notes / Recommended Actions

1. **Port and Protocol Analysis (`CommandLine`)**
   Check which port was opened. Ports like `4444` (Metasploit), `443` (often disguised as web traffic), or unusual high-number ports require immediate investigation.

2. **Rule Name Verification (`name=...`)**
   Evaluate the use of Masquerading techniques. Attackers often name rules "Core_Update", "Windows Defender Service", or similar names to evade quick visual inspection.

3. **Parent Process Identification**
   If using Sysmon logs, verify which process generated `netsh.exe`. If started by `cmd.exe` or `powershell.exe` in unusual contexts, the probability of an attack is very high.

4. **Containment (Remediation)**
   Isolate the machine and promptly delete the malicious rule from the firewall via GPO or a secure remote connection.
