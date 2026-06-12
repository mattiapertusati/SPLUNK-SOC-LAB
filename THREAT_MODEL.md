# 🎯 Threat Modeling & Detection Strategy Framework

Questo documento definisce il **Threat Model** formale applicato al progetto `SPLUNK-SOC-LAB`. L'obiettivo di questo framework è giustificare la progettazione delle regole di rilevamento (SPL, KQL, Sigma) sulla base dei profili di minaccia simulati, della superficie di attacco esposta e degli obiettivi aziendali di mitigazione del rischio.

---

## 👥 1. Attacker Profiles (Profili di Minaccia)

Il laboratorio simula le attività tattiche e procedurali di due macro-categorie di attori malevoli, focalizzandosi sulle fasi successive alla violazione iniziale (*Post-Exploitation*).

### 🔴 Profilo A: Advanced Persistent Threat (APT) / Cybercrime (Post-Phishing)
* **Vettore di Accesso Iniziale:** Esecuzione di payload malevoli da parte di un utente interno ingannato tramite campagne di phishing mirate (*Spear-Phishing Attachment/Link*).
* **Capacità e Risorse:** Elevate. L'attaccante utilizza strumenti di automazione, script offuscati e framework di Command & Control (C2) avanzati.
* **Obiettivi:** Persistenza a lungo termine nell'infrastruttura Active Directory, Privilege Escalation a Domain Admin, movimenti laterali per identificare asset critici ed esfiltrazione di dati sensibili.
* **Comportamento in Lab:** Simulato attraverso l'uso di comandi PowerShell codificati (`T1059.001`), creazione di task pianificati persistenti (`T1053.005`) e tecniche di movimento laterale via PsExec (`T1569.002`).

### 🟤 Profilo B: Malicious Insider (Minaccia Interna)
* **Vettore di Accesso Iniziale:** Accesso fisico o logico legittimo all'endpoint aziendale tramite credenziali valide (es. dipendente infedele o amministratore IT compromesso).
* **Capacità e Risorse:** Medie. Possiede una conoscenza nativa della topologia di rete e dei sistemi di difesa aziendali.
* **Obiettivi:** Sabotaggio industriale, interruzione delle Security Operations, furto di credenziali amministrative o manipolazione dei log per nascondere attività illecite.
* **Comportamento in Lab:** Simulato attraverso la disattivazione mirata del Windows Firewall (`T1562.004`), il tampering delle difese antivirus (`T1562.001`) e la cancellazione intenzionale dei log di Sicurezza di Windows (`T1070.001`).

---

## 🏗️ 2. Attack Surface Mapping (Mappatura della Superficie di Attacco)

La topologia di rete del `DetectionLab` espone quattro componenti infrastrutturali critici. Ognuno rappresenta un obiettivo strategico differente per l'attaccante.

[ WIN10-ENDPOINT ] --------> ( WEF-SERVER ) --------> [ SPLUNK-SIEM ]
        |
        v
[ SRV-DC-01 (AD) ]

### 1. WIN10-ENDPOINT (Postazioni di Lavoro Client)
* **Ruolo nel Modello:** È la prima linea di difesa e il punto d'ingresso primario per il *Profilo A*.
* **Rischi Critici:** Esecuzione di codice non autorizzato, furto di credenziali locali in memoria (LSASS), modifiche alle chiavi di registro di persistenza ed evasione dei controlli antivirus locali.

### 2. SRV-DC-01 (Active Directory Domain Controller)
* **Ruolo nel Modello:** Il "Crown Jewel" (l'asset più prezioso) dell'intera infrastruttura.
* **Rischi Critici:** Compromissione totale del dominio tramite abuso di privilegi, manipolazione degli account utente AD, aggiunta illegittima di membri ai gruppi amministrativi (`Administrators` / `Domain Admins`) e persistenza a livello di directory.

### 3. WEF-SERVER (Windows Event Forwarding)
* **Ruolo nel Modello:** L'arteria centrale della visibilità difensiva. Raccoglie i log Sysmon e Security dagli endpoint e li instrada verso il SIEM.
* **Rischi Critici:** Accecamento tattico del SOC. Se l'attaccante compromette o interrompe il servizio WEF, il SIEM smette di ricevere telemetria, permettendo all'attaccante di muoversi nell'ombra senza generare allarmi centralizzati.

### 4. SPLUNK-LOGGER (SIEM Centralizzato)
* **Ruolo nel Modello:** Il cervello operativo delle Security Operations.
* **Rischi Critici:** Tentativi di elusione tramite saturezione dei log (Log Flooding) o tentativi indiretti di bypassare le logiche delle query di correlazione studiando i pattern di esclusione dei falsi positivi.

---

## 🛡️ 3. Detection Objectives & MITRE Alignment (Obiettivi di Rilevamento)

La strategia ingegneristica applicata in questo repository non mira a rilevare "qualsiasi cosa", ma si concentra sulla massimizzazione della telemetria nei punti di snodo critici della Kill Chain, dove l'attaccante è costretto a compiere azioni rumorose.

| Obiettivo Strategico | Tattica MITRE | Tecniche Coperte | Razionale Ingegneristico (Il "Perché") |
| :--- | :--- | :--- | :--- |
| **Negare l'Esecuzione Stealth** | Execution / Defense Evasion | `T1059.001` (Encoded PowerShell) | Gli attaccanti abusano di PowerShell codificando i payload in Base64 per eludere i controlli statici di stringa. Rilevare la codifica permette di intercettare l'attacco a prescindere dal tipo di malware utilizzato. |
| **Proteggere l'Integrità dell'Identità** | Persistence / Privilege Escalation | `T1136.001` (User Creation)<br>`T1548.002` (UAC Bypass / Group Abuse) | La creazione di account locali o l'elevazione non autorizzata nel gruppo `Administrators` sono anomalie strutturali severe. Monitorare queste variazioni previene il consolidamento dell'accesso. |
| **Garantire la Sopravvivenza dei Log** | Defense Evasion | `T1070.001` (Clear Event Logs)<br>`T1562.001` (Disable Defender) | Un attaccante che tenta di accecare il SOC cancellando i log o spegnendo l'antivirus sta palesando la sua presenza. Questo rilevamento funge da "tripwire" (filo d'inciampo) ad altissima priorità. |
| **Rompere la Persistenza** | Persistence | `T1053.005` (Scheduled Tasks) | I task pianificati che puntano a directory temporanee (es. `\Temp`) sono il metodo standard per mantenere l'accesso dopo un riavvio. Intercettare la loro creazione blocca l'attaccante sul nascere. |
| **Isolare il Movimento Laterale** | Lateral Movement | `T1569.002` (PsExec)<br>`T1563.002` (RDP Hijacking) | Impedire l'espansione dell'attaccante dall'endpoint iniziale verso il Domain Controller. Monitorare l'uso abusivo di strumenti amministrativi nativi (`tscon.exe`, `PSEXESVC`) interrompe la catena di compromissione prima che diventi sistemica. |
