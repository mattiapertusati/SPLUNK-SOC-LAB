# Validation Report: Correlation Rule - Lateral Persistence

## General Information

* **Correlation Name:** Multi-Stage Attack: Lateral Movement & Persistence
* **Reference Rule:** `13-Correlation-Lateral-Persistence.md`
* **Severity:** CRITICAL
* **Objective:** Detect lateral movement through PsExec followed by persistence establishment and local firewall manipulation.

## The Attack Chain (Simulated Kill Chain)

The attacker moves laterally and establishes persistence on the system (within 24 hours).

**Phase 1: Lateral Movement (PsExec Service Execution)**

```cmd id="z8p3k6"
psexec.exe \\WIN10-ENDPOINT -s cmd.exe
```

**Phase 2: Persistence (Scheduled Task)**

```cmd id="m4q7t1"
schtasks /create /tn "WindowsUpdateCore" /tr "C:\Temp\beacon.exe" /sc onstart /ru SYSTEM
```

**Phase 3: Defense Evasion (Firewall Modification for C2)**

```cmd id="n9v2c5"
netsh advfirewall firewall add rule name="AllowC2" dir=in action=allow protocol=TCP localport=4444
```

<img width="842" height="320" alt="Screenshot 2026-06-14 173043" src="https://github.com/user-attachments/assets/14b42027-c445-4ade-9563-267f25abf2ea" />

---

## Expected Telemetry

1. `EventCode 7045` (Service Creation: PSEXESVC)
2. `EventCode 4698` (A scheduled task was created)
3. `EventCode 4688` with `netsh firewall` command

## Correlated Splunk Query (SPL)

```SPL id="e7w2k9"
(index=wineventlog OR index=sysmon) 
(EventCode=7045 "*PSEXESVC*") OR (EventCode=4698) OR (EventCode=4688 "*netsh*" "*firewall*")
| transaction host maxspan=24h
| search "*PSEXESVC*" AND EventCode=4698 AND "*netsh*"
| eval Attack_Chain="CRITICAL ALERT: Lateral Movement Execution -> Persistence via Scheduled Task -> Firewall Modification"
| table _time, host, duration, Attack_Chain
```

## Validation Result and Screenshot

The rule successfully identified the behavioral pattern of post-compromise lateral movement.

**Result:** `PASS`

<img width="1197" height="348" alt="Screenshot 2026-06-14 173134" src="https://github.com/user-attachments/assets/fe374ad2-2a55-4343-9eb5-3818ce8b3573" />
