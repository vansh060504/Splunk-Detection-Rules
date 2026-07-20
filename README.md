# Splunk Detection Rules

![Splunk](https://img.shields.io/badge/Splunk-Enterprise-green)
![Windows](https://img.shields.io/badge/Windows-Security%20Events-blue)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-red)
![License](https://img.shields.io/badge/License-MIT-yellow)

A collection of Splunk SPL detection rules developed for Windows Security monitoring, authentication analytics, and SOC detection engineering.

This repository demonstrates practical detection engineering using Windows Security Events, Splunk Search Processing Language (SPL), and the MITRE ATT&CK framework. The detections focus on identifying authentication attacks, suspicious account activity, and abnormal user behavior commonly investigated by Security Operations Center (SOC) analysts.

---

# Repository Overview

Modern Security Operations Centers (SOCs) rely heavily on Security Information and Event Management (SIEM) platforms to collect, analyze, and investigate security events generated across enterprise environments. Splunk enables security analysts to transform raw Windows Event Logs into actionable detections that can identify suspicious activities before they become security incidents.

This repository documents practical Splunk detection rules created for Windows Security monitoring. Each detection is designed to identify common attack techniques targeting user authentication and account management. These detection rules follow industry best practices and align with the MITRE ATT&CK framework to provide meaningful threat visibility.

The repository is intended for:

- SOC Analysts
- Blue Team Engineers
- Detection Engineers
- Cybersecurity Students
- Splunk Learners
- Windows Security Enthusiasts

---

# Objectives

The primary objectives of this repository are to:

- Develop practical Splunk SPL detection rules.
- Detect common authentication-based attack techniques.
- Improve Windows Security Event monitoring.
- Map detections to the MITRE ATT&CK framework.
- Demonstrate detection engineering methodologies.
- Build reusable SOC detection content.
- Strengthen investigation workflows using Windows Event Logs.

---

# Detection Methodology

Each detection included in this repository follows a structured detection engineering approach.

1. Identify a Windows Security Event associated with attacker activity.
2. Analyze how attackers abuse the event.
3. Develop SPL detection logic.
4. Reduce false positives wherever possible.
5. Map the detection to the MITRE ATT&CK framework.
6. Document investigation procedures.
7. Validate the detection using lab-generated events.

The detailed implementation for every detection is available in its respective folder and includes:

- SPL Query
- Sample Output
- References

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

# Windows Security Event IDs Covered

| Event ID | Description |
|-----------|-------------|
| 4624 | Successful Logon |
| 4625 | Failed Logon |
| 4720 | User Account Created |
| 4740 | User Account Locked Out |

---

# MITRE ATT&CK Coverage

| Technique | Description |
|-----------|-------------|
| T1078 | Valid Accounts |
| T1110 | Brute Force |
| T1110.003 | Password Spraying |
| T1136 | Create Account |

---

# Detection Overview

## Authentication

Authentication logs provide valuable visibility into user activity across Windows environments. Monitoring these events enables security analysts to identify credential attacks, account compromise, unauthorized access attempts, and abnormal authentication behavior.

---

# 1. Account Lockout Detection

## Objective

Detect Windows account lockout events that may indicate brute-force attacks, password spraying, repeated failed authentication attempts, or compromised accounts.

### Threat Description

Windows locks an account after a configurable number of failed authentication attempts. While this behavior protects user accounts from password guessing attacks, repeated account lockouts can also indicate malicious activity targeting user credentials.

Monitoring these events allows SOC analysts to identify attacks before an attacker successfully gains access.

### Windows Event

**Event ID 4740 — A user account was locked out**

### MITRE ATT&CK

| Technique | Description |
|-----------|-------------|
| T1110 | Brute Force |

### Detection Logic

This detection monitors Windows Security Event ID 4740 to identify user accounts that become locked after exceeding the organization's configured authentication threshold.

Rather than focusing on individual failed logins, this detection highlights accounts that have already reached the lockout policy, making them higher-priority investigation candidates.

### Investigation Steps

- Review the affected user account.
- Identify the originating workstation.
- Review preceding failed login events.
- Check whether privileged accounts were targeted.
- Determine whether the activity aligns with normal user behavior.

### Possible Impact

- Credential attacks
- Password spraying
- User account disruption
- Unauthorized access attempts

### Common False Positives

- Forgotten passwords
- Expired credentials
- Cached passwords
- Password synchronization issues
- Mobile devices using outdated passwords

### Analyst Recommendation

Correlate Event ID 4740 with failed authentication events (4625) and successful authentication events (4624) to determine whether the lockout resulted from malicious activity or user error.

📂 **Implementation**

```
authentication/account-lockout-detection/
```

---

# 2. After Hours Login Detection

## Objective

Identify successful user logins occurring outside approved business hours that may indicate compromised accounts or unauthorized access.

### Threat Description

Attackers frequently use stolen credentials during evenings, weekends, or holidays when security monitoring is reduced and legitimate user activity is lower.

Monitoring logins occurring outside expected working hours helps security analysts identify suspicious authentication behavior that may otherwise remain unnoticed.

### Windows Event

**Event ID 4624 — Successful Logon**

### MITRE ATT&CK

| Technique | Description |
|-----------|-------------|
| T1078 | Valid Accounts |

### Detection Logic

This detection monitors successful authentication events occurring outside the organization's defined business hours.

Although after-hours activity is not always malicious, correlating these events with user roles, VPN usage, privileged access, and historical behavior significantly improves investigation accuracy.

### Investigation Steps

- Verify whether the user normally works outside business hours.
- Review login source.
- Review authentication history.
- Check VPN connections.
- Verify recent password changes.
- Correlate with privileged account activity.

### Possible Impact

- Account compromise
- Unauthorized remote access
- Insider threats
- Privilege abuse

### Common False Positives

- Night shift employees
- IT administrators
- Maintenance activities
- Remote workers
- On-call engineers

### Analyst Recommendation

Always validate user schedules before escalating. Correlate authentication activity with endpoint telemetry and network logs to determine whether the login was expected.

📂 **Implementation**

```
authentication/after-hours-login-detection/
```

---

# 3. Brute Force / Password Spray Detection

## Objective

Detect repeated failed authentication attempts originating from a single source that may indicate brute-force attacks or password spraying campaigns.

### Threat Description

Password attacks remain one of the most common techniques used to compromise Windows environments.

Rather than exploiting software vulnerabilities, attackers attempt to guess valid user credentials through repeated authentication attempts. Password spraying differs from traditional brute force by attempting a small number of common passwords across many user accounts, making it harder to detect.

### Windows Event

**Event ID 4625 — Failed Logon**

### MITRE ATT&CK

| Technique | Description |
|-----------|-------------|
| T1110 | Brute Force |
| T1110.003 | Password Spraying |

### Detection Logic

This detection identifies repeated failed authentication attempts originating from the same source within a defined period.

Monitoring authentication failures enables analysts to identify attack patterns before successful authentication occurs.

### Investigation Steps

- Review the source IP address.
- Identify targeted accounts.
- Check for successful logins following failures.
- Review authentication frequency.
- Investigate whether privileged accounts were targeted.
- Correlate with firewall and endpoint telemetry.

### Possible Impact

- Credential compromise
- Unauthorized access
- Password spraying
- Brute-force attacks
- Account lockouts

### Common False Positives

- Forgotten passwords
- Password expiration
- Service account misconfiguration
- Automated authentication scripts

### Analyst Recommendation

Investigate repeated authentication failures immediately, particularly when multiple accounts are targeted from the same source. Early identification significantly reduces the likelihood of successful credential compromise.

📂 **Implementation**

```
authentication/brute-force-password-spray/
```

---

# 4. Failed Login Anomaly Detection

## Objective

Identify abnormal spikes in failed authentication attempts that significantly deviate from the normal authentication baseline.

### Threat Description

Not every brute-force attack generates thousands of failed logins. Modern attackers often perform slow, distributed, or low-volume attacks to avoid traditional threshold-based detections.

By identifying statistical anomalies instead of relying solely on fixed thresholds, SOC analysts can detect suspicious authentication activity that may otherwise remain unnoticed.

### Windows Event

**Event ID 4625 — Failed Logon**

### MITRE ATT&CK

| Technique | Description |
|-----------|-------------|
| T1110 | Brute Force |

### Detection Logic

Instead of looking only for a predefined number of failed logins, this detection establishes a baseline of normal authentication activity and highlights sudden increases that exceed expected behavior.

Anomaly-based detections are particularly effective for identifying low-and-slow attacks, compromised systems generating unexpected authentication failures, or changes in user behavior.

### Investigation Steps

- Compare current activity with historical authentication trends.
- Identify the affected systems.
- Determine whether failures originate from a single or multiple sources.
- Review successful authentication events occurring after the anomaly.
- Correlate with endpoint and network security logs.

### Possible Impact

- Credential attacks
- Password guessing
- Compromised endpoints
- Unauthorized authentication attempts

### Common False Positives

- Organization-wide password resets
- Authentication service outages
- Bulk software deployments
- Active Directory synchronization issues

### Analyst Recommendation

Baseline authentication activity should be reviewed periodically to reduce false positives. Correlating authentication anomalies with endpoint telemetry provides better confidence during investigations.

📂 **Implementation**

```
authentication/failed-login-anomaly/
```

---

# 5. Multiple Account Login Detection

## Objective

Detect a single system successfully authenticating multiple user accounts within a defined time period.

### Threat Description

Attackers who obtain access to a workstation often attempt to authenticate using multiple user accounts while performing lateral movement or validating stolen credentials.

A single endpoint successfully logging into several different accounts within a short period may indicate credential abuse, password spraying, shared credentials, or compromised administrative systems.

### Windows Event

**Event ID 4624 — Successful Logon**

### MITRE ATT&CK

| Technique | Description |
|-----------|-------------|
| T1078 | Valid Accounts |

### Detection Logic

This detection identifies systems that successfully authenticate multiple unique user accounts during a specified time window.

Although administrative systems and jump servers may naturally authenticate several users, unexpected multi-account activity on standard workstations should be investigated.

### Investigation Steps

- Identify the originating computer.
- Review authenticated user accounts.
- Verify whether the host is an administrative workstation.
- Review authentication history.
- Investigate lateral movement activity.
- Correlate with endpoint security alerts.

### Possible Impact

- Credential compromise
- Lateral movement
- Unauthorized access
- Privilege abuse

### Common False Positives

- Shared workstations
- Domain Controllers
- Jump servers
- Helpdesk systems
- Administrative maintenance

### Analyst Recommendation

Combine this detection with endpoint monitoring and network telemetry to distinguish legitimate administrative activity from malicious credential abuse.

📂 **Implementation**

```
authentication/multi-account-login-detection/
```

---

# Account Management

Windows account management events provide visibility into administrative activities that directly affect user identities. Monitoring these events helps identify persistence techniques, unauthorized account creation, and privilege abuse.

---

# 6. Suspicious User Creation Detection

## Objective

Detect newly created Windows user accounts that may indicate unauthorized persistence or privilege escalation.

### Threat Description

Threat actors frequently create new user accounts after compromising a system to maintain long-term access. Unauthorized account creation is a common persistence technique that enables attackers to regain access even after passwords are changed.

Monitoring user creation events allows analysts to identify suspicious administrative activity before additional compromise occurs.

### Windows Event

**Event ID 4720 — User Account Created**

### MITRE ATT&CK

| Technique | Description |
|-----------|-------------|
| T1136 | Create Account |

### Detection Logic

This detection monitors Windows Security Event ID 4720 and identifies every newly created user account.

Analysts can verify whether account creation follows normal onboarding procedures or whether unauthorized accounts have been introduced into the environment.

### Investigation Steps

- Verify the legitimacy of the newly created account.
- Identify the administrator responsible for creating the account.
- Review assigned permissions.
- Check group memberships.
- Determine whether privileged groups were modified.
- Review additional administrative activity.

### Possible Impact

- Persistence
- Privilege escalation
- Insider threats
- Unauthorized administrative access

### Common False Positives

- HR onboarding
- IT provisioning
- Automated identity management systems
- Domain migrations

### Analyst Recommendation

All unexpected account creation events should be investigated immediately. Newly created privileged accounts require the highest investigation priority.

📂 **Implementation**

```
account-management/suspicious-user-creation/
```

---

# SOC Investigation Workflow

The detections included in this repository are designed to support a structured Security Operations Center (SOC) investigation process.

```
Windows Event Logs
        │
        ▼
Splunk Data Ingestion
        │
        ▼
Detection Rule Execution
        │
        ▼
Alert Generation
        │
        ▼
Event Validation
        │
        ▼
Threat Investigation
        │
        ▼
Incident Response
        │
        ▼
Documentation & Lessons Learned
```

This workflow demonstrates how raw Windows Security Events are transformed into actionable security alerts that enable analysts to investigate and respond to potential threats.

---

# Skills Demonstrated

## SIEM & Detection Engineering

- Splunk Enterprise
- Search Processing Language (SPL)
- Detection Engineering
- SIEM Content Development
- Alert Logic Design

## Windows Security

- Windows Security Event Analysis
- Authentication Monitoring
- Account Management Monitoring
- Windows Event Log Investigation
- Event Correlation

## Threat Detection

- Brute Force Detection
- Password Spraying Detection
- Account Lockout Monitoring
- User Behavior Analysis
- Authentication Anomaly Detection
- User Account Monitoring

## Security Operations

- SOC Investigation Workflow
- Incident Triage
- Threat Hunting
- Alert Validation
- MITRE ATT&CK Mapping
- Blue Team Operations

---

# Learning Outcomes

Through this project I gained practical experience in:

- Writing efficient Splunk SPL queries
- Developing SIEM detection logic
- Understanding Windows Security Events
- Mapping detections to the MITRE ATT&CK framework
- Investigating authentication-based attacks
- Detecting suspicious account activity
- Reducing false positives during investigations
- Documenting security detections
- Building reusable SOC detection content
- Strengthening threat hunting methodologies

---

# Future Improvements

This repository will continue to grow with additional Windows detection rules and SOC use cases, including:

- PowerShell Activity Detection
- RDP Login Monitoring
- Privilege Escalation Detection
- Service Installation Monitoring
- Scheduled Task Detection
- Registry Persistence Detection
- Windows Defender Tampering
- Suspicious Process Creation
- WMI Activity Monitoring
- Lateral Movement Detection

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

This repository is intended for educational purposes and personal cybersecurity lab environments.

The detection rules included in this repository were developed to demonstrate detection engineering concepts, Windows Security Event analysis, and Splunk SPL query development.

No production logs, customer information, organizational assets, confidential data, hostnames, usernames, IP addresses, or proprietary security content are included.

All examples, sample outputs, and documentation have been sanitized or anonymized to protect privacy and security while maintaining technical accuracy.
