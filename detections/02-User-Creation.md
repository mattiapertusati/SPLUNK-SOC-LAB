# Detection of Local User Creation

### Description
This rule detects the creation of a new local user account on the system. Attackers often create fake accounts (`backdoor`) to ensure persistent access to the infrastructure, bypassing any password changes made by the initially compromised user.

## MITRE ATT&CK
* **Tactic:** Persistence (TA0003)
* **Technique:** Create Account (T1136)
* **Sub-technique:** Local Account (T1136.001)

## Alert Metadata
* **Severity:** High
* **Confidence:** Medium 
* **Impact:** High

---

### SPL Query
```splunk
index=wineventlog sourcetype=XmlWinEventLog EventCode=4720 NOT SubjectUserName="*$" NOT SubjectUserName="SYSTEM"
| rename SubjectUserName as Creator_Account, TargetUserName as Created_Account
| stats earliest(_time) as Primo_Evento, latest(_time) as Ultimo_Evento, count by host, Creator_Account, Created_Account
```

### Possible False Positives
* Creation of legitimate accounts (Onboarding).
* Creation of temporary accounts with maximum privileges and a short expiration date for urgent maintenance or updates.

---

### Triage Notes / Recommended Actions

1. **Origin Verification (`Subject`)**
   Analyze the `SubjectUserName` field to determine who created the account. If the user does not belong to the IT department or if the action happens outside normal working hours, the event is critical.

2. **Endpoint Context (`Host`)**
   Evaluate the target machine (`host`). The creation of a local account on a standard corporate laptop (Endpoint) is highly suspicious compared to creation on a Domain Controller.

3. **Hunting for Related Activities (`Escalation`)**
   Look for subsequent logs (such as EventCode 4732) to check if the new account (`TargetUserName`) was immediately added to high-privilege groups, like Administrators or Remote Desktop Users.
