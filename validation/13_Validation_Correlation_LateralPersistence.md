# 🧪 Validation Report: Correlation Rule - Lateral Persistence

## 📋 Informazioni Generali
* **Correlation Name:** Multi-Stage Attack: Lateral Movement & Persistence
* **Regola di Riferimento:** `13-Correlation-Lateral-Persistence.md`
* **Severity:** 🔴 CRITICAL
* **Obiettivo:** Rilevare il salto laterale tramite PsExec seguito dall'instaurazione di persistenza e manipolazione del firewall locale.

## 🎯 The Attack Chain (Kill Chain Simulata)
L'attaccante si sposta lateralmente ed esegue l'ancoraggio al sistema (entro 24 ore).

**Fase 1: Lateral Movement (Esecuzione servizio PsExec)**
```cmd
psexec.exe \\WIN10-ENDPOINT -s cmd.exe
```

**Fase 2: Persistence (Operazione Pianificata)**
```cmd
schtasks /create /tn "WindowsUpdateCore" /tr "C:\Temp\beacon.exe" /sc onstart /ru SYSTEM
```

**Fase 3: Defense Evasion (Modifica Firewall per C2)**
```cmd
netsh advfirewall firewall add rule name="AllowC2" dir=in action=allow protocol=TCP localport=4444
```

<img width="842" height="320" alt="Screenshot 2026-06-14 173043" src="https://github.com/user-attachments/assets/14b42027-c445-4ade-9563-267f25abf2ea" />

---

## 📡 Telemetria Attesa
1. `EventCode 7045` (Service Creation: PSEXESVC)
2. `EventCode 4698` (A scheduled task was created)
3. `EventCode 4688` con comando `netsh firewall`

## 🔴 Correlated Splunk Query (SPL)

```SPL
(index=wineventlog OR index=sysmon) 
(EventCode=7045 "*PSEXESVC*") OR (EventCode=4698) OR (EventCode=4688 "*netsh*" "*firewall*")
| transaction host maxspan=24h
| search "*PSEXESVC*" AND EventCode=4698 AND "*netsh*"
| eval Attack_Chain="ALLARME CRITICO: Esecuzione di Lateral Movement -> Persistenza tramite Operazione Pianificata -> Modifica al Firewall"
| table _time, host, duration, Attack_Chain
```

## ✅ Risultato della Validazione e Screenshot
La regola ha identificato con successo il pattern comportamentale del movimento laterale post-compromissione.

**Risultato:** `PASS` 🟢

<img width="1197" height="348" alt="Screenshot 2026-06-14 173134" src="https://github.com/user-attachments/assets/fe374ad2-2a55-4343-9eb5-3818ce8b3573" />
