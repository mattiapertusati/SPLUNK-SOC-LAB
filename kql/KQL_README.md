# Microsoft Sentinel KQL Detections

This folder contains detection rules translated into **KQL (Kusto Query Language)**, ready to be implemented within a **Log Analytics Workspace** or as **Analytics Rules** in Microsoft Sentinel.

## How to Use These Rules

1. Access the **Microsoft Sentinel** portal.
2. Navigate to **Configuration > Analytics**.
3. Click **Create > Scheduled query rule**.
4. Copy the code contained in the `.kql` files in this folder and paste it into the **Rule query** field.
5. Configure the entity mapping using the projected fields (e.g., `Computer`, `Account`).

## KQL Rule Coverage

The included queries cover the entire Kill Chain simulated in the lab, using standard Microsoft 365 Defender and Sentinel tables:

* **`DeviceProcessEvents` / `SecurityEvent`**: Used to track anomalous process creation (e.g., `tscon.exe` for RDP Hijacking, `schtasks.exe` for persistence, or the use of obfuscated PowerShell parameters).
* **`SecurityEvent` (EventID 4720, 4732, 4697)**: Used to monitor Active Directory and local accounts (malicious user creation or privilege escalation in the `Administrators` group).

## Field Normalization Note

All queries were written to be resilient to evasion techniques. When the command line may be stored in different attributes depending on the type of logging agent (MDE or classic Security Logs), the `coalesce()` function has been implemented to normalize the fields and avoid false negatives.
