# 🔵 Microsoft Sentinel KQL Detections

Questa cartella contiene le regole di rilevamento tradotte in **KQL (Kusto Query Language)**, pronte per essere implementate all'interno di un **Log Analytics Workspace** o come **Analytics Rules** in Microsoft Sentinel.

## 🛠️ Come Utilizzare queste Regole

1.  Accedi al portale di **Microsoft Sentinel**.
2.  Naviga su **Configuration > Analytics**.
3.  Clicca su **Create > Scheduled query rule**.
4.  Copia il codice contenuto nei file `.kql` di questa cartella e incollalo nel campo **Rule query**.
5.  Configura il mapping delle entità utilizzando i campi proiettati (es. `Computer`, `Account`).

## 🗂️ Copertura delle Regole KQL

Le query incluse coprono l'intera Kill Chain simulata nel laboratorio, sfruttando le tabelle standard di Microsoft 365 Defender e Sentinel:

* **`DeviceProcessEvents` / `SecurityEvent`**: Utilizzate per tracciare la creazione dei processi anomali (es. `tscon.exe` per RDP Hijacking, `schtasks.exe` per le persistente, o l'uso di parametri offuscati in PowerShell).
* **`SecurityEvent` (EventID 4720, 4732, 4697)**: Dedicate al monitoraggio del Active Directory e degli account locali (creazione utenti malevoli o scalate di privilegi nel gruppo Administrators).

## 📌 Nota sulla Normalizzazione dei Campi
Tutte le query sono state scritte per essere resilienti all'evasione. Nei casi in cui la riga di comando possa trovarsi in attributi differenti a seconda del tipo di agente di log (MDE o Log di Sicurezza classico), è stata implementata la funzione `coalesce()` per normalizzare i campi ed evitare falsi negativi.
