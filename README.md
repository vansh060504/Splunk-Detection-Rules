# Splunk Detection Rules

![Splunk](https://img.shields.io/badge/Splunk-Enterprise-green)
![Windows](https://img.shields.io/badge/Windows-Security%20Events-blue)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-red)
![License](https://img.shields.io/badge/License-MIT-yellow)

A collection of Splunk SPL detection rules developed for Windows Security monitoring, authentication analytics, and SOC detection engineering.

This repository demonstrates practical detection engineering using Windows Security Events, Splunk Search Processing Language (SPL), and the MITRE ATT&CK framework. The detections focus on identifying authentication attacks, suspicious account activity, and abnormal user behavior commonly investigated by Security Operations Center (SOC) analysts.

---

# Repository Overview

## Objectives

- Develop practical Splunk SPL detection rules.
- Detect common authentication-based attack techniques.
- Improve Windows Security Event monitoring.
- Map detections to the MITRE ATT&CK framework.
- Document SOC investigation methodologies.
- Build reusable detection engineering content.

---

# Detection Coverage

| Detection | Category | Windows Event ID | MITRE ATT&CK |
|------------|----------|-----------------:|--------------|
| Account Lockout Detection | Authentication | 4740 | T1110 |
| After Hours Login Detection | Authentication | 4624 | T1078 |
| Brute Force / Password Spray Detection | Authentication | 4625 | T1110 / T1110.003 |
| Failed Login Anomaly Detection | Authentication | 4625 | T1110 |
| Multiple Account Login Detection | Authentication | 4624 | T1078 |
| Suspicious User Creation Detection | Account Management | 4720 | T1136 |

---

# Detection Overview

## Authentication

### Account Lockout Detection

Detects Windows account lockout events that may indicate brute-force attacks, password spraying, or repeated failed authentication attempts.

📂 Documentation available in:

```
authentication/account-lockout-detection/
```

---

### After Hours Login Detection

Identifies successful user logins occurring outside normal business hours to help detect compromised accounts or unauthorized access.

📂 Documentation available in:

```
authentication/after-hours-login-detection/
```

---

### Brute Force / Password Spray Detection

Detects repeated failed authentication attempts originating from a single source that may indicate brute-force or password spraying attacks.

📂 Documentation available in:

```
authentication/brute-force-password-spray/
```

---

### Failed Login Anomaly Detection

Uses statistical analysis to identify abnormal spikes in failed authentication events that differ from normal user behavior.

📂 Documentation available in:

```
authentication/failed-login-anomaly/
```

---

### Multiple Account Login Detection

Identifies a single source successfully authenticating multiple user accounts within a short period of time.

📂 Documentation available in:

```
authentication/multi-account-login-detection/
```

---

## Account Management

### Suspicious User Creation Detection

Monitors newly created Windows user accounts to identify unauthorized account creation or persistence techniques.

📂 Documentation available in:

```
account-management/suspicious-user-creation/
```

---

# Skills Demonstrated

- Splunk Enterprise
- SPL (Search Processing Language)
- Detection Engineering
- Windows Security Event Analysis
- Authentication Monitoring
- Threat Hunting
- Security Monitoring
- SOC Investigation
- MITRE ATT&CK Mapping
- Blue Team Operations

---

# Learning Outcomes

Through this project I gained practical experience in:

- Writing efficient SPL queries
- Building SIEM detection logic
- Investigating Windows authentication events
- Mapping detections to MITRE ATT&CK
- Detecting brute-force and password spraying attacks
- Monitoring user account activity
- Developing reusable SOC detection content
- Improving security investigation workflows

---

# Repository Structure

```
splunk-detection-rules/
│
├── authentication/
│   ├── account-lockout-detection/
│   ├── after-hours-login-detection/
│   ├── brute-force-password-spray/
│   ├── failed-login-anomaly/
│   └── multi-account-login-detection/
│
├── account-management/
│   └── suspicious-user-creation/
│
├── references/
├── LICENSE
└── README.md
```

---

# Disclaimer

This repository is intended for educational purposes and personal lab environments.

No production logs, organizational assets, confidential information, customer data, hostnames, usernames, IP addresses, or screenshots from corporate environments are included.

All examples are sanitized or anonymized to protect privacy and security.
