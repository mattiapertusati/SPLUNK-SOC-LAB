# Vendor-Agnostic Sigma Rules

Welcome to the section dedicated to **Sigma** rules. Sigma represents the *de facto* standard for writing security signatures in an open, readable format that is fully independent of the SIEM in use.

## Portability and Compilation

The rules contained in this folder are written in **YAML** format. They can be instantly converted into the native query language of any enterprise SIEM (Splunk, Elastic, Sentinel, QRadar, ArcSight) using the following methods:

1. **Uncoder.io (Web Interface):** Copy the YAML code from the file and paste it into [uncoder.io](https://uncoder.io) to obtain the query in the desired format.
2. **Sigma CLI (Automation):** Install the official tool and compile from the command line:

   ```bash
   sigma convert -t splunk -p windows_sysmon regola.yml
   ```

## Sigma Rule Structure

Each file strictly follows the enterprise security standard:

* **`logsource`**: Defines the log category (e.g., `process_creation`) and operating system (`windows`).
* **`detection`**: Contains the exact Boolean logic of the attack, combining strings, wildcards, and system paths.
* **`falsepositives`**: Lists known legitimate behaviors to filter during the *tuning* phase.
* **`level`**: Indicates the alert severity (Low, Medium, High, Critical) mapped to the actual risk.
