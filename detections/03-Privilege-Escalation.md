# Detection of Local Privilege Escalation

### Description
This rule detects the addition of a user account to a privileged local group (for example, `Administrators`). Attackers perform this maneuver to elevate their permissions (`Privilege Escalation`) or to grant broad operational rights to a newly created fake account (`backdoor`).

## MITRE ATT&CK
* **Tactic:** Privilege Escalation (TA0004) / Persistence (TA0003)
* **Technique:** Permission Groups Discovery (T1069) or Account Manipulation (T1098)
* **Sub-technique:** Local Groups (T1069.001) / Dominant for this action: T1098 

## Alert Metadata
* **Severity:** High
* **Confidence:** Medium
* **Impact:** High

---

### SPL Query
```splunk
index=wineventlog EventCode=4732 Group_Name=Administrators
| eval Group_Target=coalesce(Group_Name, TargetUserName)
| eval Creator_Account=coalesce(SubjectUserName, mvindex(Account_Name, 0))
| eval Added_Account_SID=coalesce(MemberSid, mvindex(Security_ID, 1))
| table _time, host, Creator_Account, Group_Target, Added_Account_SID
```

### Possible False Positives
* Promotion of legitimate accounts.
* Creation of temporary accounts by the Helpdesk or automatic activities by the role assigner (LAPS).

---

### Triage Notes / Recommended Actions

1. **SID Resolution (`Security Identifier`)**
   The native log 4732 often does not record the name of the added user in clear text, but only the `Security_ID` (SID). The analyst must take the value extracted in the `Added_Account_SID` field and look backward (using EventCode 4720 or 4624) to translate the SID into the clear text account name.

2. **Action Validation**
   Check if adding the user to the `Administrators` group is documented by a support ticket. If the action happens during unusual hours or is performed by a non-IT account (`Creator_Account`), isolate the host immediately.

3. **Chain Control (`Kill Chain`)**
   Look for unusual activities performed by that SID in the following minutes, such as disabling Windows Defender or creating firewall rules.
