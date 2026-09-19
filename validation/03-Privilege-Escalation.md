## Validation Report: Local Privilege Escalation

### 1. Attack Execution

* **Tool:** Atomic Red Team
* **Test Performed:** Test 1 - UAC
* **Command Executed:**

  ```powershell
  Invoke-AtomicTest T1548.002 -TestNumbers 1 -PathToAtomicsFolder "C:\AtomicRedTeam\atomics"
  ```

<img width="821" height="181" alt="Screenshot 2026-06-11 112656 (2)" src="https://github.com/user-attachments/assets/1c0f7ebf-d553-4008-9ff3-b3342a202ba3" />

### 2. Telemetry & Logs

* **Data Source:** Windows Security Event Log
* **Expected EventID:** 4732

<img width="897" height="1183" alt="Screenshot 2026-06-11 112656" src="https://github.com/user-attachments/assets/af728044-e179-4efb-a0b8-c214be29de0b" />

### 3. Detection & Validation

* **Rule Name:** Local Privilege Escalation via PowerShell
* **Test Result:** Triggered = YES
* **False Positives:** NO

### Splunk (SPL)

```spl
index=wineventlog EventCode=4732 Group_Name=Administrators
| eval Group_Target=coalesce(Group_Name, TargetUserName)
| eval Creator_Account=coalesce(SubjectUserName, mvindex(Account_Name, 0))
| eval Added_Account_SID=coalesce(MemberSid, mvindex(Security_ID, 1))
| table _time, host, Creator_Account, Group_Target, Added_Account_SID
```

### Microsoft Sentinel (KQL)

```kql
SecurityEvent
| where EventID == 4732 and TargetUserName == "Administrators"
| extend Group_Target = TargetUserName
| extend Creator_Account = SubjectAccount
| extend Added_Account_SID = TargetSid
| project TimeGenerated, Computer, Creator_Account, Group_Target, Added_Account_SID
```

### Sigma Rule (Agnostic)

See the **privilege_escalation.yml** file in the repository for the complete rule.

### 4. Validation Results

1. **Attack Executed:** YES
2. **Logs Generated:** YES
3. **Detection Triggered:** YES
4. **False Positives:** Low.

<img width="1185" height="370" alt="Screenshot 2026-06-11 112712" src="https://github.com/user-attachments/assets/ae765326-3b96-45e2-9353-78bfa6329077" />
