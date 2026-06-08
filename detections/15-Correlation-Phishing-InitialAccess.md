# 🚨 Multi-Stage Attack: Phishing Initial Access & C2

### Descrizione
Questa regola di **Correlazione Avanzata** traccia il classico vettore di accesso iniziale tramite Spearphishing. L'allarme si attiva se, in una finestra massima di 15 minuti sulla stessa macchina, un applicativo della suite Office (Word o Excel) genera in modo anomalo un processo figlio a riga di comando (CMD o PowerShell), e successivamente quest'ultimo avvia una connessione di rete esterna per scaricare il payload di secondo livello (C2).

## 🎯 MITRE ATT&CK
* **Tactic:** Initial Access (TA0001), Execution (TA0002), Command and Control (TA0011)
* **Technique:** Phishing: Spearphishing Attachment (T1566.001), Command and Scripting Interpreter (T1059), Application Layer Protocol (T1071)

## 🚦 Alert Metadata
* **Severity:** HIGH
* **Confidence:** High (Office che lancia PowerShell e va su internet è quasi sempre un'attività malevola)
* **Impact:** High

### Query SPL (Correlation Engine)
```splunk
(index=wineventlog OR index=sysmon)
(
  (EventCode=4688 OR EventCode=1) ("*winword.exe*" OR "*excel.exe*") ("*cmd.exe*" OR "*powershell.exe*")
) OR (
  EventCode=3 ("*powershell.exe*" OR "*cmd.exe*")
)
| transaction host maxspan=15m
| search ("*winword.exe*" OR "*excel.exe*") AND ("*cmd.exe*" OR "*powershell.exe*") AND EventCode=3
| eval Attack_Chain="ALLARME CRITICO: Esecuzione Macro (Office) -> Lancio Shell -> Connessione C2"
| table _time, host, duration, Attack_Chain
```

### Triage & Azioni Consigliate
Questo evento indica il momento esatto del "Paziente Zero".

1. Recupero Evidenze: Individuare il file malevolo originale (.docx, .docm, .xlsx) aperto dall'utente e isolarlo.

2. Analisi di Rete: Estrarre l'IP o il dominio contattato al punto 2 dell'attacco (EventCode 3) e bloccarlo sul proxy/firewall aziendale per impedire ulteriori download di payload.

3. Controllo a Tappeto: Cercare nei log della posta elettronica se lo stesso file allegato è stato inviato ad altri dipendenti dell'azienda.
