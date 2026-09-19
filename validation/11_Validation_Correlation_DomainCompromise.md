# Validation Report: Correlation Rule - Domain Compromise

## General Information

* **Correlation Name:** Multi-Stage Attack: Possible Domain Compromise
* **Reference Rule:** `11-Correlation-Domain-Compromise.md`
* **Severity:** CRITICAL
* **Objective:** Validate the tracking of an attacker who creates a user account, escalates privileges, and clears the logs to hide their traces.

## The Attack Chain (Simulated Kill Chain)

The following commands were executed in rapid succession (within 24 hours) from an administrative command prompt on the Windows 10 endpoint.

**Phase 1: Persistence (Local Account Creation)**

```cmd
net user BackupAdmin Password123! /add
```

**Phase 2: Privilege Escalation (Adding the Account to the Administrators Group)**

```cmd
net localgroup Administrators BackupAdmin /add
```

**Phase 3: Defense Evasion (Clearing Security Logs)**

```cmd
wevtutil cl Security
```

<img width="512" height="168" alt="Screenshot 2026-06-14 162949" src="https://github.com/user-attachments/assets/651dd9fb-5996-411e-bb96-62e3bde946f7" />

---

## Expected Telemetry

1. `EventCode 4720` (Account Creation)
2. `EventCode 4732` (Member Added to Local Group - Administrators)
3. `EventCode 1102` (Audit Log Cleared)

## Correlated Splunk Query (SPL)

```SPL id="f3j8m2"
(index=wineventlog OR index=sysmon) 
(
  EventCode=4720
) OR (
  EventCode=4732
) OR ( 
  EventCode=1102
)
| transaction host maxspan=24h
| search EventCode=4720 EventCode=4732 EventCode=1102 Group_Name=Administrators
| eval Attack_Chain="CRITICAL ALERT: Local Account Creation -> Account Added to Administrators -> Log Clearing"
| table _time, host, duration, Attack_Chain
```

## Validation Result and Screenshot

By executing the attack chain in the laboratory environment, the correlation query successfully combined the three separate events under the same `host` using the `transaction` command.

**Result:** `PASS`

<img width="1194" height="501" alt="Screenshot 2026-06-14 170349" src="https://github.com/user-attachments/assets/b94d92dd-f9aa-4bbd-8d23-0e2cc3281b2e" />
