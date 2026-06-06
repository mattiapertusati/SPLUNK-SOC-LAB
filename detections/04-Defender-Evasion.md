# 🚨 Detection of Windows Defender Evasion (Real-Time Protection Disabled)

### Descrizione
Rileva il tentativo di disattivazione della protezione in tempo reale di Windows Defender tramite il Cmdlet nativo `Set-MpPreference`. Gli attaccanti eseguono questo comando per "spegnere le telecamere" prima di scaricare o eseguire payload maligni (malware, ransomware) sull'endpoint, evitando il blocco immediato da parte dell'antivirus.

## 🎯 MITRE ATT&CK
* **Tactic:** Defense Evasion (TA0005)
* **Technique:** Impair Defenses (T1562)
* **Sub-technique:** Disable or Modify Tools (T1562.001)

## 🚦 Alert Metadata
* **Severity:** High
* **Confidence:** Medium
* **Impact:** High

### Query SPL
```splunk
index=wineventlog source="*PowerShell*" (EventCode=4103 OR EventCode=4104) "Set-MpPreference"


| eval Script_Content=coalesce(Message, ScriptBlockText, _raw)
| regex Script_Content="(?i)-DisableR(ealtimeMonitoring)?\s+(1|\$true)"
| table _time, host, EventCode, Script_Content
```

### ⚠️ Possibili Falsi Positivi
* Interventi legittimi da parte di amministratori IT per test o risoluzione problemi.
* Esecuzione di script di automazione che lavorano solo con l`antivirus disattivato.

---

### Note di Triage / Azioni Consigliate

1. **Analisi del Contesto (Payload)**
   Ispezionare il campo `Message` per confermare che il parametro passato sia `$true` (o `1`), che indica l'effettiva volontà di spegnere il monitoraggio, e non `$false` (che lo riattiverebbe).

2. **Caccia a comandi correlati**
    Un attaccante che usa PowerShell per spegnere Defender, spesso lo usa subito dopo per scaricare il malware. Cercare nello stesso intervallo temporale esecuzioni di `Invoke-WebRequest` (iwr) o `Net.WebClient`.
   
3. **Contenimento (Remediation)**
   Se l'azione è malevola, isolare immediatamente l'host dalla rete aziendale. La riattivazione di Windows Defender dovrà essere forzata tramite Group Policy (GPO) o tramite la console EDR centrale, poiché l'attaccante potrebbe aver alterato i permessi locali.
