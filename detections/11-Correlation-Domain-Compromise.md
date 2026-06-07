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
index=wineventlog EventCode IN (4720, 4732, 1102)

| stats min(_time) as Primo_Evento, max(_time) as Ultimo_Evento, values(EventCode) as Eventi_Rilevati, count by host
| eval duration_minutes = round((Ultimo_Evento - Primo_Evento) / 60, 2)
| filter duration_minutes <= 30

| filter mvcount(Eventi_Rilevati) == 3
| eval Attack_Chain="Rilevata Kill Chain: Creazione Utente -> Privilege Escalation -> Log Clearing"
| table Primo_Evento, Ultimo_Evento, host, Attack_Chain, duration_minutes
```
## Triage & Azioni Consigliate
Trattandosi di una regola di correlazione ad alta fedeltà, se questo allarme suona l'host è quasi certamente compromesso.

1. Isolare l'host dalla rete aziendale immediatamente.

2. Controllare i log precedenti per capire quale vettore di accesso iniziale è stato utilizzato (es. RDP, phishing, exploit).
