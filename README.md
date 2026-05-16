
# Network Intrusion Prevention System (IPS 2.0)

## Overview

IPS 2.0 is a modular, Python-based Network Intrusion Prevention System designed for the real-time detection and prevention of sophisticated cyberattacks. It operates by intercepting network packets using `iptables` and `NetfilterQueue`, inspecting them via multiple engines, and automatically blocking, logging, or allowing traffic based on threat severity.

## Value and Importance

Modern cyber threats—such as zero-day exploits, encrypted payloads, and polymorphic malware—have completely outpaced traditional, static signature-based firewalls. Static rule-based systems struggle to detect evolving threats and often generate a high number of false positives.

IPS 2.0 addresses this gap by introducing a smart, hybrid approach that combines rule-based detection, anomaly analysis, and machine learning. This allows the system to adapt to unknown attacks and respond instantly with minimal human intervention, providing post-compromise visibility and a multi-layered defense that reduces noise and boosts accuracy.

## Key Features

* **Multi-Layered Detection:** Combines signature-based keyword scanning with Machine Learning (XGBoost + Random Forest for payloads, Decision Trees for files) to catch both known and zero-day threats.


* **Brute-Force Mitigation:** Automatically detects and blocks brute-force login attempts for protocols like SSH and RDP (e.g., blocking an IP after 5 failed attempts in 60 seconds).


* **Anti-DoS/DDoS Protection:** Monitors traffic patterns to detect and mitigate flooding attacks, including SYN floods (>100 packets/sec) and ICMP floods (>30 pings/sec).


* **Intelligent Payload Scanning:** Inspects network payloads for obfuscated shell commands, raw binary custom exploits, injection-ready shellcodes, and Metasploit-generated payloads.


* **Automated File Analysis & Quarantine:** Continuously watches download directories to detect new files, analyzes PE (Portable Executable) headers, and quarantines malware-infected files using a trained ML model.


* **High Performance:** Capable of processing approximately 10,000 packets per second utilizing Python's multiprocessing capabilities with a detection rate of >95% and a false positive rate of <5%.



## System Architecture

The system is built on a highly modular architecture:

* **`main.py` (Central Controller):** Orchestrates all subsystems, manages the multiprocessing packet queue, handles iptables redirection, and enforces allow/drop/log decisions.


* **`firewall_engine.py`:** Applies flexible, user-defined JSON rules (from `rules.json`) to filter packets based on headers, ports, and protocols.


* **`dos_protector.py`:** Tracks packet rates per IP and implements dynamic thresholds to stop flooding attacks.


* **`payload_analyzer.py`:** Decodes payloads (Base64, URL, etc.) and analyzes them using both a keyword matching engine and an ML model for binary data.


* **`file_analyzer.py` & `file_monitor.py`:** Detects new file creations, extracts static PE features via the `pefile` library, and classifies the file using a Decision Tree model.



## Installation & Usage

### Prerequisites

* Linux environment (requires `iptables` for network traffic redirection).


* Python 3.



### Setup

1. Clone the repository and navigate to the project directory.
2. Install the required dependencies:
```bash
pip install scapy netfilterqueue watchdog pefile joblib

```



(Note: These libraries handle packet manipulation, Linux packet queueing, directory monitoring, PE feature extraction, and ML model serialization, respectively.)



### Running the IPS

Execute the main controller with root privileges (required for network interception):

```bash
sudo python3 main.py

```

(Note: Ensure your `rules.json`, `keywords.json`, and `whitelist.txt` are properly configured in the `config/` directory before launch.)

## Limitations & Future Work

While IPS 2.0 is highly effective, there are current limitations:

* **Encrypted Traffic:** The system cannot currently inspect encrypted SSL/TLS traffic.


* **Model Retraining:** The static ML models require periodic retraining to detect entirely new families of malware.


* **Resource Intensive:** Deep packet inspection and ML inference can be resource-intensive under extremely heavy network loads.



Future enhancements aim to integrate MITM proxy tools for SSL decryption, ingest live external threat intelligence feeds, and add a web-based UI dashboard for interactive monitoring.

## Team Contributions

This project was developed by Class BS-CYS-IV-B:

* **Muhammad Fahad:** System architecture, ML dataset curation, Payload Scan Module, and central controller (`main.py`).


* **Ayesha Wajid:** ML development environment, File Analyzer Module, and IPS research.


