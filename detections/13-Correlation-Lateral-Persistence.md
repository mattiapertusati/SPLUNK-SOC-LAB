# 🚨 Multi-Stage Attack: Lateral Movement & Persistence

### Descrizione
Questa regola di **Correlazione Avanzata** traccia una manovra tipica di post-compromissione. L'allarme scatta se, entro 45 minuti sulla stessa macchina, un attaccante si muove lateralmente installando il servizio PsExec, crea un'operazione pianificata per garantirsi la persistenza al riavvio e altera le regole del firewall di Windows per facilitare le comunicazioni di Comando e Controllo (C2).

## 🎯 MITRE ATT&CK
* **Tactic:** Lateral Movement (TA0008), Persistence (TA0003), Defense Evasion (TA0005)
* **Technique:** SMB/Windows Admin Shares (T1021.002), Scheduled Task (T1053.005), Impair Defenses: Disable or Modify System Firewall (T1562.004)

## 🚦 Alert Metadata
* **Severity:** CRITICAL
* **Confidence:** High
* **Impact:** Critical

### Query SPL (Correlation Engine)
```splunk
(index=wineventlog OR index=sysmon) 
( 
  EventCode=7045 "*PSEXESVC*" 
) OR ( 
  EventCode=4698 
) OR ( 
  EventCode=4688 "*netsh*" "*firewall*"
)
| transaction host maxspan=45m
| search "*PSEXESVC*" AND EventCode=4698 AND "*netsh*"
| eval Attack_Chain="ALLARME CRITICO: Esecuzione di Lateral Movement -> Persistenza tramite Operazione Pianificata -> Modifica al Firewall"
| table _time, host, duration, Attack_Chain
```

### Triage & Azioni Consigliate

Questo è un forte indicatore che l'attaccante ha già superato le difese perimetrali e si sta diffondendo nella rete.

1. **Contenimento:** Isolare immediatamente l'host infetto per bloccare ulteriori movimenti laterali.

2. **Reverse Tracking:** Identificare da quale IP è partita la connessione PsExec per trovare il "Paziente Zero" (l'host da cui l'attaccante è saltato).

3. **Bonifica:** Rimuovere l'operazione pianificata anomala e ripristinare le policy originali del firewall.
