# 🚨 Multi-Stage Attack: Credential Theft & Evasion

### Descrizione
Questa regola di **Correlazione Avanzata** fa scattare un allarme critico solo se viene rispettata una specifica "Kill Chain" temporale. L'attaccante esegue tre azioni sulla stessa macchina entro un massimo di 60 minuti: 
1. Disattiva le protezioni di Windows Defender.
2. Lancia un payload PowerShell offuscato.
3. Effettua il dump della memoria del processo LSASS per rubare le credenziali.

## 🎯 MITRE ATT&CK
* **Tactic:** Defense Evasion (TA0005), Execution (TA0002), Credential Access (TA0006)
* **Technique:** Impair Defenses (T1562.001), Obfuscated Files or Information (T1027), OS Credential Dumping: LSASS Memory (T1003.001)

## 🚦 Alert Metadata
* **Severity:** CRITICAL
* **Confidence:** High (Una sequenza del genere generata da un utente/admin legittimo è estremamente rara e viola tutte le policy di sicurezza)
* **Impact:** Critical

### Query SPL (Correlation Engine)
```splunk
(index=wineventlog OR index=sysmon) 
( 
  (EventCode=1 OR EventCode=4688) ("* -enc *" OR "* -encodedcommand *") 
) OR ( 
  ("*DisableRealtimeMonitoring*" OR "*Set-MpPreference*") 
) OR ( 
  EventCode=10 TargetImage="*\\lsass.exe" 
)
| transaction host maxspan=60m
| search "lsass.exe" AND ("-enc" OR "-encodedcommand") AND ("DisableRealtimeMonitoring" OR "Set-MpPreference")
| eval Attack_Chain="ALLARME CRITICO: Esecuzione Powershell Encoded -> Disattivazione Defender -> Accesso e Dumping di LSASS"
| table _time, host, duration, Attack_Chain
```

### Triage & Azioni Consigliate
Trattandosi di una catena d'attacco complessa ad altissima fedeltà, se questo allarme suona ci troviamo di fronte a un incidente di sicurezza (Indicident Response) in corso.

1. **Isolare immediatamente** l'host infetto dalla rete per prevenire movimenti laterlai
2. **Resete delle credenziali:** Poichè c'è stato un accesso a LSASS, forzare il reset delle password per tutti gli utenti che avevano una sessione attiva su quell'host
3. **Analisy del Payload:** Estrarre la query della timeline dell'allarme e decodificare il Base64 per capire quale C2 stava contattando l'attacante.

