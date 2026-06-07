# 🚨 Multi-Stage Attack: Possible Domain Compromise

### Descrizione
Questa è una regola di **Correlazione Avanzata**. Non cerca un singolo evento, ma traccia una "Kill Chain" specifica. L'allarme scatta solo se, sulla stessa macchina, un attaccante crea un utente fittizio (4720), lo promuove ad Amministratore (4732) e successivamente cancella i log di sicurezza per coprire le proprie tracce (1102).

## 🎯 MITRE ATT&CK
* **Tactic:** Persistence, Privilege Escalation, Defense Evasion
* **Technique:** Account Manipulation (T1098), Indicator Removal on Host (T1070)

## 🚦 Alert Metadata
* **Severity:** CRITICAL
* **Confidence:** High (Una sequenza del genere generata da un utente legittimo è estremamente rara e viola le policy di sicurezza)
* **Impact:** Critical

### Query SPL (Correlation Engine)
```splunk
(index=wineventlog OR index=sysmon) 
(
  EventCode=4720
) OR (
  EventCode=4732
) OR ( 
  EventCode=1102
)
| transaction host maxspan=30m
| search EventCode=4720 AND (EventCode=4732 AND Group_Name=Administrators) AND EventCode=1102
| eval Attack_Chain="ALLARME CRITICO: Creazione account in Locale -> Account inserito in Administrators -> Puliza Log"
| table _time, host, duration, Attack_Chain
```
## Triage & Azioni Consigliate
Trattandosi di una regola di correlazione ad alta fedeltà, se questo allarme suona l'host è quasi certamente compromesso.

1. Isolare l'host dalla rete aziendale immediatamente.

2. Controllare i log precedenti per capire quale vettore di accesso iniziale è stato utilizzato (es. RDP, phishing, exploit).
