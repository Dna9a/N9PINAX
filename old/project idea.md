# Final Year Project Ideas (Cybersecurity)

This document organizes possible final year project topics and clarifies scope, tools, and expected outcomes.

## 1) SIEM Platform Using Wazuh

Build a Security Information and Event Management (SIEM) setup with Wazuh to collect, analyze, and visualize security events.

### Core Features
- Centralized log collection from endpoints and servers.
- Alerting rules for suspicious activities.
- Dashboard for monitoring incidents and trends.

### Suggested Stack
- Wazuh
- Elastic Stack / OpenSearch (depending on setup)
- Linux server environment

## 2) Honeypot Deployment and Analysis

Deploy a honeypot to attract and observe malicious traffic, then analyze attacker behavior.

### Core Features
- Deploy one or more honeypot services (SSH, web, or IoT simulation).
- Capture attacker IPs, payloads, and attack patterns.
- Generate periodic threat intelligence summaries.

### Suggested Stack
- Cowrie or T-Pot
- Python scripts for log parsing
- Simple dashboard for attack statistics

## 3) File Type Identification and Risk Classifier

Create a parser that identifies real file type (not only by extension) and flags potentially executable or suspicious files.

### Core Features
- Detect file type using magic numbers/signatures.
- Identify executable formats (EXE, ELF, Mach-O, scripts).
- Produce a risk score and explanation.

### Suggested Stack
- Python
- python-magic / custom signature parsing

## 4) Phishing Email Simulation and Awareness Tool

Build a controlled internal simulation platform to generate realistic phishing scenarios and track user awareness.

### Core Features
- Email template generator.
- Click/open tracking for awareness metrics.
- Reporting panel by team or campaign.

### Important Note
- This must be used ethically and only in authorized environments.

### Suggested Stack
- Python (backend)
- Flask or FastAPI
- SQLite/PostgreSQL for campaign data

## 5) Network Device Scanner with Visual Dashboard

Build your own lightweight network scanner (not just using Nmap directly), including device fingerprinting with MAC vendor lookup and a visual dashboard.

### Core Features
- Discover hosts on local network.
- Scan common ports and basic service info.
- Identify manufacturer via MAC OUI lookup.
- Show results in a dashboard.

### Suggested Stack
- Python + Scapy (packet crafting and discovery)
- Flask (web interface)
- Optional Raspberry Pi deployment

### Cybersecurity Focus
- Secure the dashboard (authentication, input validation, rate limiting).
- Secure scanner execution and stored scan data.

## 6) Intrusion Detection System (IDS)

Monitor traffic and detect suspicious behavior such as port scanning or possible DDoS activity.

### Pipeline
[Network Traffic] -> [Packet Capture] -> [Analysis Rules] -> [Alert System]

### Core Features
- Packet capture (Scapy/Python).
- Rule-based detection (high request rate, scan patterns, abnormal traffic).
- Alert logging and notification.
- Optional live dashboard.

### Suggested Stack
- Python
- Scapy
- Socket
- Optional: Snort or Suricata integration

## 7) Web Application Vulnerability Scanner

Build a scanner that crawls input fields and tests for common vulnerabilities such as SQL injection and XSS.

### Core Features
- Discover forms and parameters.
- Test payloads safely and log findings.
- Classify vulnerabilities by severity.
- Export a professional report (PDF/HTML).

### Suggested Stack
- Python
- requests + BeautifulSoup / Playwright (optional)
- Reporting library (ReportLab, WeasyPrint, or similar)

## Additional Ideas (My Suggestions)

## 8) Threat Intelligence Aggregator

Collect Indicators of Compromise (IOCs) from public feeds and compare them with local logs.

### Features
- IOC feed ingestion (IPs, domains, hashes).
- Matching engine against collected events.
- Daily threat summary dashboard.

## 9) Secure Password Audit Toolkit

Analyze password policy quality in a lab environment and generate compliance reports.

### Features
- Policy checker (length, complexity, rotation).
- Hash strength and cracking resistance estimation.
- Actionable remediation recommendations.

## 10) SOC Analyst Assistant (Alert Triage)

Build a tool that helps prioritize alerts by risk, confidence, and context.

### Features
- Ingest alerts from logs/IDS.
- Deduplicate and group related alerts.
- Assign priority scores and investigation hints.

## Recommended Direction

If you want a strong balance between networking + cybersecurity + software engineering, the best options are:
- Network Device Scanner with dashboard.
- IDS with alerting pipeline.
- Web Application Vulnerability Scanner with professional reporting.

## Final Note

For any selected topic, prepare a complete README that includes:
- Project goal and scope.
- Architecture diagram.
- Installation and usage steps.
- Test methodology.
- Security and ethical considerations.
- Limitations and future improvements.
