# Splunk Detection Rules

![Splunk](https://img.shields.io/badge/Splunk-Enterprise-green)
![Windows](https://img.shields.io/badge/Windows-Security%20Events-blue)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-red)
![License](https://img.shields.io/badge/License-MIT-yellow)

A collection of Splunk SPL detection rules for Windows Security monitoring, authentication analytics, and SOC detection engineering.

---

## Repository Structure

```
splunk-detection-rules/
│
├── authentication/
├── account-management/
├── references/
└── README.md
```

---

## Detection Rules

| Detection | Event ID | MITRE ATT&CK |
|------------|---------|--------------|
| Account Lockout Detection | 4740 | T1110 |
| After Hours Login Detection | 4624 | T1078 |
| Brute Force / Password Spray | 4625 | T1110 / T1110.003 |
| Failed Login Anomaly | 4625 | T1110 |
| Multiple Account Login | 4624 | T1078 |
| Suspicious User Creation | 4720 | T1136 |

---

## Categories

### Authentication

- Account Lockout Detection
- After Hours Login Detection
- Brute Force / Password Spray
- Failed Login Anomaly
- Multiple Account Login

### Account Management

- Suspicious User Creation

---

## Technologies Used

- Splunk Enterprise
- SPL (Search Processing Language)
- Windows Security Event Logs
- MITRE ATT&CK
- Windows Event IDs

---

## Disclaimer

This repository contains detection logic created for educational purposes and personal lab environments.

No production logs, customer information, company assets, confidential information, or sensitive data are included.
