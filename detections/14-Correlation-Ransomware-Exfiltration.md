# 🚨 Multi-Stage Attack: Ransomware Data Staging & Impact

### Descrizione
Questa regola di **Correlazione Avanzata** traccia le fasi finali e più devastanti di un attacco Ransomware. L'allarme si attiva se, entro 60 minuti sulla stessa macchina, un attaccante comprime file sensibili in un archivio (Data Staging), utilizza utility di rete a riga di comando per esfiltrare l'archivio verso un server esterno e, infine, distrugge le copie di sicurezza locali (Shadow Copies) per impedire il ripristino dei dati.

## 🎯 MITRE ATT&CK
* **Tactic:** Collection (TA0009), Exfiltration (TA0010), Impact (TA0040)
* **Technique:** Archive Collected Data (T1560), Exfiltration Over Alternative Protocol (T1048), Inhibit System Recovery (T1490)

## 🚦 Alert Metadata
* **Severity:** CRITICAL
* **Confidence:** High
* **Impact:** Critical

### Query SPL (Correlation Engine)
```splunk
(index=wineventlog OR index=sysmon)
(
  (EventCode=4688 OR EventCode=1) ("*7z.exe*" OR "*WinRAR.exe*")
) OR ( 
  (EventCode=4688 OR EventCode=1) ("*rclone.exe*" OR "*curl.exe*")
) OR ( 
  (EventCode=4688 OR EventCode=1) ("*vssadmin*" AND "*delete shadows*")
)
| transaction host maxspan=60m
| search ("*7z.exe*" OR "*WinRAR.exe*") AND ("*rclone.exe*" OR "*curl.exe*") AND "*vssadmin*" AND "*delete shadows*"
| eval Attack_Chain = "ATTACCO CRITICO: Compressione Dati -> Esfiltrazione su Internet -> Distruzione Shadow Copies"
| table _time, host, duration, Attack_Chain
```

### Triage & Azioni Consigliate

Questo è uno scenario di Crisi (P1 Incident). L'esfiltrazione e la distruzione dei backup indicano che il ransomware è a un passo dal cifrare l'intero disco.

1. **Isolamento Immediato:** Disconnettere fisicamente o logicamente la macchina dalla rete.

2. **Ricerca IoC:** Identificare verso quale indirizzo IP o dominio stavano comunicando `curl.exe` o `rclone.exe` per bloccarlo a livello di firewall perimetrale.

3. **Controllo Danni:** Verificare tramite i log di rete quanti Mega/Giga di dati sono stati esfiltrati.
