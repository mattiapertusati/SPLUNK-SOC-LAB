# Threat Modeling & Detection Strategy Framework

This document defines the formal **Threat Model** applied to the `SPLUNK-SOC-LAB` project. The objective of this framework is to justify the design of detection rules (SPL, KQL, Sigma) based on the simulated threat profiles, the exposed attack surface, and the organization's risk mitigation objectives.

---

## 1. Attacker Profiles

The lab simulates the tactical and procedural activities of two main categories of malicious actors, focusing on the stages following the initial compromise (*Post-Exploitation*).

### Profile A: Advanced Persistent Threat (APT) / Cybercrime (Post-Phishing)

* **Initial Access Vector:** Execution of malicious payloads by an internal user who was deceived through targeted phishing campaigns (*Spear-Phishing Attachment/Link*).
* **Capabilities and Resources:** High. The attacker uses automation tools, obfuscated scripts, and advanced Command & Control (C2) frameworks.
* **Objectives:** Long-term persistence within the Active Directory infrastructure, Privilege Escalation to Domain Admin, lateral movement to identify critical assets, and exfiltration of sensitive data.
* **Lab Behavior:** Simulated through the use of encoded PowerShell commands (`T1059.001`), creation of persistent scheduled tasks (`T1053.005`), and lateral movement techniques using PsExec (`T1569.002`).

### Profile B: Malicious Insider (Insider Threat)

* **Initial Access Vector:** Legitimate physical or logical access to the corporate endpoint through valid credentials (e.g., a malicious employee or a compromised IT administrator).
* **Capabilities and Resources:** Medium. The attacker has native knowledge of the network topology and the organization's security defenses.
* **Objectives:** Industrial sabotage, disruption of Security Operations, theft of administrative credentials, or manipulation of logs to hide unauthorized activities.
* **Lab Behavior:** Simulated through targeted Windows Firewall disabling (`T1562.004`), antivirus defense tampering (`T1562.001`), and intentional clearing of Windows Security logs (`T1070.001`).

---

## 2. Attack Surface Mapping

The `DetectionLab` network topology exposes four critical infrastructure components. Each represents a different strategic target for the attacker.

[ WIN10-ENDPOINT ] --------> ( WEF-SERVER ) --------> [ SPLUNK-SIEM ]
|
v
[ SRV-DC-01 (AD) ]

### 1. WIN10-ENDPOINT (Client Workstations)

* **Role in the Model:** It is the first line of defense and the primary entry point for *Profile A*.
* **Critical Risks:** Unauthorized code execution, theft of local credentials from memory (LSASS), modifications to persistence registry keys, and evasion of local antivirus controls.

### 2. SRV-DC-01 (Active Directory Domain Controller)

* **Role in the Model:** The "Crown Jewel" (the most valuable asset) of the entire infrastructure.
* **Critical Risks:** Full domain compromise through privilege abuse, manipulation of AD user accounts, unauthorized addition of members to administrative groups (`Administrators` / `Domain Admins`), and directory-level persistence.

### 3. WEF-SERVER (Windows Event Forwarding)

* **Role in the Model:** The central artery of defensive visibility. It collects Sysmon and Security logs from endpoints and forwards them to the SIEM.
* **Critical Risks:** Tactical SOC blindness. If the attacker compromises or disrupts the WEF service, the SIEM stops receiving telemetry, allowing the attacker to operate without generating centralized alerts.

### 4. SPLUNK-LOGGER (Centralized SIEM)

* **Role in the Model:** The operational brain of Security Operations.
* **Critical Risks:** Evasion attempts through log flooding or indirect attempts to bypass correlation query logic by studying false-positive exclusion patterns.

---

## 3. Detection Objectives & MITRE Alignment

The engineering strategy applied in this repository does not aim to detect "everything", but focuses on maximizing telemetry at critical points of the Kill Chain where the attacker is forced to perform noisy actions.

| Strategic Objective            | MITRE Tactic                       | Covered Techniques                                                    | Engineering Rationale (The "Why")                                                                                                                                                                                                              |
| :----------------------------- | :--------------------------------- | :-------------------------------------------------------------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Prevent Stealth Execution**  | Execution / Defense Evasion        | `T1059.001` (Encoded PowerShell)                                      | Attackers abuse PowerShell by encoding payloads in Base64 to evade static string-based controls. Detecting encoding makes it possible to identify the attack regardless of the type of malware being used.                                     |
| **Protect Identity Integrity** | Persistence / Privilege Escalation | `T1136.001` (User Creation)<br>`T1548.002` (UAC Bypass / Group Abuse) | The creation of local accounts or unauthorized elevation into the `Administrators` group are significant structural anomalies. Monitoring these changes helps prevent access from being consolidated.                                          |
| **Ensure Log Survival**        | Defense Evasion                    | `T1070.001` (Clear Event Logs)<br>`T1562.001` (Disable Defender)      | An attacker attempting to blind the SOC by deleting logs or disabling antivirus protection is revealing their presence. This detection acts as a high-priority "tripwire".                                                                     |
| **Break Persistence**          | Persistence                        | `T1053.005` (Scheduled Tasks)                                         | Scheduled tasks that point to temporary directories (e.g., `\Temp`) are a common method for maintaining access after a reboot. Detecting their creation can stop the attacker early in the attack chain.                                       |
| **Contain Lateral Movement**   | Lateral Movement                   | `T1569.002` (PsExec)<br>`T1563.002` (RDP Hijacking)                   | Prevent the attacker from expanding from the initial endpoint toward the Domain Controller. Monitoring the abusive use of native administrative tools (`tscon.exe`, `PSEXESVC`) can interrupt the compromise chain before it becomes systemic. |
