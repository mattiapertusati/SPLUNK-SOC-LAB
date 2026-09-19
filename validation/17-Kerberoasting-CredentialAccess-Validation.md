# Validation Report: Detection 17 - Kerberoasting

## Simulated Scenario

**MITRE ATT&CK:** T1558.003 (Kerberoasting)
**Description:** Request for a Ticket Granting Service (TGS) ticket using weak encryption (RC4) for a service account (SPN), allowing offline cracking.

## Lab Execution

Executed using Rubeus:
`.\Rubeus.exe kerberoast /format:hashcat /outfile:hashes.txt`

## Results

* **SPL Triggered:** True Positive
* **KQL Triggered:** True Positive
* **Detected Events:** EventCode 4769 (Ticket Type: 0x17 RC4).
