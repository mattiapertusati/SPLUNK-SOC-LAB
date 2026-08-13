# Validation Report: Detection 17 - Kerberoasting

## 🎯 Scenario Simulato
**MITRE ATT&CK:** T1558.003 (Kerberoasting)
**Descrizione:** Richiesta di Ticket Granting Service (TGS) con crittografia debole (RC4) verso un account di servizio (SPN) per il cracking offline.

## 💥 Esecuzione in Lab
Eseguito tramite Rubeus:
`.\Rubeus.exe kerberoast /format:hashcat /outfile:hashes.txt`

## 📊 Risultati
* **SPL Triggered:** ✅ True Positive
* **KQL Triggered:** ✅ True Positive
* **Eventi Rilevati:** EventCode 4769 (Ticket Type: 0x17 RC4).
