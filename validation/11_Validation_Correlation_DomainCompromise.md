# 🧪 Validation Report: Correlation Rule - Domain Compromise

## 📋 Informazioni Generali
* **Correlation Name:** Multi-Stage Attack: Possible Domain Compromise
* **Regola di Riferimento:** `11-Correlation-Domain-Compromise.md`
* **Severity:** 🔴 CRITICAL
* **Obiettivo:** Validare il tracciamento di un attaccante che crea un utente, scala i privilegi e cancella i log per nascondere le tracce.

## 🎯 The Attack Chain (Kill Chain Simulata)
I seguenti comandi sono stati eseguiti in rapida successione (entro 30 minuti) sul prompt dei comandi amministrativo dell'endpoint Windows 10.

**Fase 1: Persistence (Creazione Account Locale)**
```cmd
net user BackupAdmin Password123! /add
```

**Fase 2: Privilege Escalation (Aggiunta al gruppo Administrators)**
```cmd
net localgroup Administrators BackupAdmin /add
```

**Fase 3: Defense Evasion (Cancellazione dei Log di Sicurezza)**
```cmd
wevtutil cl Security
```

<img width="512" height="168" alt="Screenshot 2026-06-14 162949" src="https://github.com/user-attachments/assets/651dd9fb-5996-411e-bb96-62e3bde946f7" />

---

## 📡 Telemetria Attesa

1. `EventCode 4720` (Account Creation)
2. `EventCode 4732` (Member Added to Local Group - Administrators)
3. `EventCode 1102` (Audit Log Cleared)

## 🔴 Correlated Splunk Query (SPL)
```SPL
(index=wineventlog OR index=sysmon) 
(
  EventCode=4720
) OR (
  EventCode=4732
) OR ( 
  EventCode=1102
)
| transaction host maxspan=24h
| search EventCode=4720 EventCode=4732 EventCode=1102 Group_Name=Administrators
| eval Attack_Chain="ALLARME CRITICO: Creazione account in Locale -> Account inserito in Administrators -> Pulizia Log"
| table _time, host, duration, Attack_Chain
```

## ✅ Risultato della Validazione e Screenshot
Eseguendo la catena di attacco in laboratorio, la query di correlazione ha unito con successo i 3 eventi separati sotto lo stesso `host` tramite il comando transaction.

**Risultato:** `PASS` 🟢

<img width="1194" height="501" alt="Screenshot 2026-06-14 170349" src="https://github.com/user-attachments/assets/b94d92dd-f9aa-4bbd-8d23-0e2cc3281b2e" />
