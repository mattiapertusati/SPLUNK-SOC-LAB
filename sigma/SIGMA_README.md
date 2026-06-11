# 🟡 Vendor-Agnostic Sigma Rules

Benvenuto nella sezione dedicata alle regole **Sigma**. Sigma rappresenta lo standard *de facto* per la scrittura di firme di sicurezza in formato aperto, leggibile e totalmente indipendente dal SIEM in uso.

## 🚀 Portabilità e Compilazione

Le regole contenute in questa cartella sono scritte in formato **YAML**. Possono essere convertite istantaneamente nella query nativa di qualsiasi SIEM aziendale (Splunk, Elastic, Sentinel, QRadar, ArcSight) utilizzando i seguenti metodi:

1.  **Uncoder.io (Interfaccia Web):** Copia il codice YAML del file e incollalo su [uncoder.io](https://uncoder.io) per ottenere la query nel formato desiderato.
2.  **Sigma CLI (Automazione):** Installa il tool ufficiale e compila da riga di comando:
    ```bash
    sigma convert -t splunk -p windows_sysmon regola.yml
    ```

## 🧠 Struttura di una Regola Sigma

Ogni file segue rigorosamente lo standard di sicurezza enterprise:
* **`logsource`**: Definisce la categoria del log (es. `process_creation`) e il sistema operativo (`windows`).
* **`detection`**: Contiene la logica booleana esatta dell'attacco, combinando stringhe, wildcard e percorsi di sistema.
* **`falsepositives`**: Elenca i comportamenti legittimi noti da filtrare durante la fase di *tuning*.
* **`level`**: Indica la severity dell'allarme (Low, Medium, High, Critical) mappata sul rischio reale.
