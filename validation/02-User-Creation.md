## Validation Report: Local User Creation

### 1. Attack Execution

* **Tool:** PowerShell
* **Test Performed:** Local User Creation
* **Command Executed:**

  ```powershell
  net user EvilHacker Password123! /add
  ```

<img width="433" height="72" alt="Screenshot 2026-06-10 224109" src="https://github.com/user-attachments/assets/5643bbf2-884f-4964-82f5-0903286da2db" />

### 2. Telemetry & Logs

* **Data Source:** Windows Security Event Log
* **Expected EventID:** 4720

<img width="901" height="1237" alt="Screenshot 2026-06-11 112052" src="https://github.com/user-attachments/assets/39072216-1440-46f1-9bdd-b0537fa29532" />

### 3. Detection & Validation

* **Rule Name:** Local User Creation via PowerShell
* **Test Result:** Triggered = YES
* **False Positives:** NO

### Splunk (SPL)

```spl
index=wineventlog EventCode=4720 
| eval Creator_Account = mvindex(Account_Name, 0)
| eval Created_Account = mvindex(Account_Name, 1)
| table _time host Creator_Account Created_Account
```

### Microsoft Sentinel (KQL)

```kql
SecurityEvent
| where EventID in (4688, 4720)
| extend Creator_Account = coalesce(SubjectAccount, Account)
| project TimeGenerated, Computer, Creator_Account, TargetAccount
```

### Sigma Rule (Agnostic)

See the **local_user_creation.yml** file in the repository for the complete rule.

### 4. Validation Results

1. **Attack Executed:** YES
2. **Logs Generated:** YES
3. **Detection Triggered:** YES
4. **False Positives:** Low.

<img width="1180" height="353" alt="Screenshot 2026-06-11 112253" src="https://github.com/user-attachments/assets/334717ea-81be-4473-8d83-47b1fab421fc" />
