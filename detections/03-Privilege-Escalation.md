# 🚨 Detection of Local User Creation

| **Metadati** | **Dettagli** |
| :--- | :--- |
| **Tecnica MITRE ATT&CK** | `T1098 - Account Manipulation` |
| **Log Source** | `Windows Security Event Log (EventCode 4732)` |

---

### Descrizione
Rileva l'aggiunta di un account utente a un gruppo locale privilegiato (es. 'Administrators'). Gli attaccanti eseguono questa manovra per elevare i propri permessi ('Privilege Escalation') o per garantire ampi diritti operativi a un account fittizio ('backdoor') appena creato.

### Query SPL
```splunk
index=wineventlog EventCode=4732 Group_Name=Administrators
| eval Creator_Account=mvindex(Account_Name, 0)
| eval Added_Account_SID=mvindex(Security_ID, 1)
| table _time, host, Creator_Account, Group_Name, Added_Account_SID
```

### ⚠️ Possibili Falsi Positivi
* Promozione di account legittimi.
* Creazioni di account temporali da Helpdesk oppure attività automatiche dell'assegnatore di ruoli (LAPS).

---

### Note di Triage / Azioni Consigliate

1. **Risoluzione del SID (Security Identifier)**
   Il log nativo 4732 spesso non registra in chiaro il nome dell'utente aggiunto, ma solo il suo 'Security_ID' (SID). L'analista deve prendere il valore estratto nel campo 'Added_Account_SID' e cercare a ritroso (EventCode 4720 o 4624) per tradurre il SID nel nome dell'account in chiaro.

2. **Validazione dell'Azione**
   Controllare se l'aggiunta dell'utente al gruppo 'Administrators' è documentata da un ticket di supporto. Se l'azione avviene in orari anomali o da parte di un account non IT ('Creator_Account'), isolare immediatamente l'host.

3. **Controllo a catena (Kill Chain)**
   Cercare attività anomale eseguite da quel SID nei minuti successivi, come disattivazione di Windows Defender o creazione di regole del firewall.
