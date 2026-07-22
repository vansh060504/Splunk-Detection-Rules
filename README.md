# Splunk Detection Rules

![Splunk](https://img.shields.io/badge/Splunk-Enterprise-green)
![Windows](https://img.shields.io/badge/Windows-Security%20Events-blue)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-red)
![License](https://img.shields.io/badge/License-MIT-yellow)

A collection of practical Splunk Search Processing Language (SPL) detection rules developed for Windows Security Event monitoring, SOC detection engineering, and threat hunting.

This repository demonstrates how Windows Security Events can be transformed into actionable security detections using Splunk Enterprise. Each detection focuses on identifying authentication attacks, account management activity, privilege escalation, and lateral movement techniques commonly investigated by Security Operations Center (SOC) analysts.

Every detection includes:

- SPL Query
- Detection Logic
- MITRE ATT&CK Mapping
- References
- Sample Output
- Recommended Alert Configuration
- Investigation Guidance

---

# Repository Overview

Security Information and Event Management (SIEM) platforms play a critical role in modern Security Operations Centers by collecting, correlating, and analyzing security events from enterprise environments.

Splunk enables analysts to convert raw Windows Event Logs into meaningful detections that help identify suspicious activity before it develops into a security incident.

This repository contains practical Splunk detection rules built using Windows Security Events. The detections focus on common attack techniques targeting authentication, account management, privilege escalation, and remote access.

Rather than relying solely on basic searches, the detections demonstrate practical detection engineering concepts such as:

- Authentication analytics
- Event correlation
- Threshold-based detection
- Windows Security Event analysis
- Risk-based alerting
- False positive reduction
- Custom field extraction using `rex`
- MITRE ATT&CK mapping

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

- Develop practical Splunk SPL detection rules for Windows Security monitoring.
- Detect authentication attacks and suspicious account activity.
- Identify privilege escalation and lateral movement techniques.
- Demonstrate real-world SIEM detection engineering concepts.
- Map detections to the MITRE ATT&CK framework.
- Build reusable SOC detection content.
- Improve Windows Security Event monitoring.
- Strengthen investigation workflows using Windows Event Logs.
- Showcase practical Splunk skills through documented detection rules.

---

# Repository Statistics

| Metric | Coverage |
|---------|----------|
| Detection Rules | 10 |
| Windows Security Event IDs | 7 |
| MITRE ATT&CK Techniques | 6 |
| Detection Categories | 4 |
| Documentation | Query, References, Sample Output, Investigation Guidance |

### Detection Categories

- Authentication
- Account Management
- Privilege Escalation
- Lateral Movement

---

# Detection Methodology

Each detection included in this repository follows a structured detection engineering workflow designed to align with Security Operations Center (SOC) best practices.

The development process consists of:

1. Identify relevant Windows Security Events.
2. Understand attacker behavior associated with the event.
3. Develop SPL detection logic.
4. Validate detections using a Windows lab environment.
5. Reduce false positives wherever possible.
6. Assign meaningful risk levels.
7. Map detections to the MITRE ATT&CK framework.
8. Document investigation procedures.
9. Include sample outputs and references.

Every detection folder contains:

- **query.spl** – Splunk SPL detection query
- **sample-output.md** – Example detection results
- **references.md** – Microsoft, Splunk, and MITRE references

---

# Detection Coverage

| Detection | Category | Windows Event ID | MITRE ATT&CK |
|------------|----------|-----------------:|--------------|
| Account Lockout Detection | Authentication | 4740 | T1110 |
| After Hours Login Detection | Authentication | 4624 | T1078 |
| Brute Force / Password Spray Detection | Authentication | 4625 | T1110 / T1110.003 |
| Failed Login Anomaly Detection | Authentication | 4625 | T1110 |
| Multiple Account Login Detection | Authentication | 4624 | T1078 |
| NTLM Authentication Spike | Authentication | 4776 | T1110 |
| Suspicious User Creation Detection | Account Management | 4720 | T1136 |
| Special Privileges Assigned | Privilege Escalation | 4672 | T1078 |
| Explicit Credential Logon | Lateral Movement | 4648 | T1078 / T1021 |
| RDP Interactive Login | Lateral Movement | 4624 (Logon Type 10) | T1021.001 |

---

# Windows Security Event IDs Covered

| Event ID | Description |
|-----------|-------------|
| 4624 | Successful Logon |
| 4625 | Failed Logon |
| 4648 | Logon Using Explicit Credentials |
| 4672 | Special Privileges Assigned to New Logon |
| 4720 | User Account Created |
| 4740 | User Account Locked Out |
| 4776 | NTLM Credential Validation |

---

# MITRE ATT&CK Coverage

| Technique | Description |
|-----------|-------------|
| T1021 | Remote Services |
| T1021.001 | Remote Desktop Protocol (RDP) |
| T1078 | Valid Accounts |
| T1110 | Brute Force |
| T1110.003 | Password Spraying |
| T1136 | Create Account |

---

# Detection Overview

The repository is organized into four primary detection categories:

- **Authentication** – Detects suspicious login activity, brute-force attacks, password spraying, NTLM authentication anomalies, and unusual authentication behavior.
- **Account Management** – Monitors user account creation and administrative changes that may indicate persistence or unauthorized account management.
- **Privilege Escalation** – Identifies logons where elevated privileges are assigned, helping detect privileged account abuse.
- **Lateral Movement** – Detects explicit credential usage and Remote Desktop Protocol (RDP) activity that may indicate attacker movement between systems.

---

# Authentication

Authentication events provide critical visibility into how users access Windows systems and network resources. Monitoring successful and failed authentication attempts enables Security Operations Center (SOC) analysts to detect credential attacks, account compromise, unauthorized access, and abnormal login behavior.

The detections in this section focus on identifying common authentication-based attack techniques, including brute-force attacks, password spraying, failed login anomalies, unusual login patterns, and NTLM authentication abuse.

---

# 1. Account Lockout Detection

## Objective

Detect Windows account lockout events that may indicate brute-force attacks, password spraying, repeated failed authentication attempts, or compromised user accounts.

### Threat Description

Windows locks user accounts after a configurable number of failed authentication attempts. While this mechanism protects against password guessing attacks, repeated account lockouts often indicate malicious attempts to compromise user credentials.

Monitoring account lockout events allows SOC analysts to identify authentication attacks before an attacker successfully gains access.

### Windows Event

**Event ID 4740 — A user account was locked out**

### MITRE ATT&CK

| Technique | Description |
|-----------|-------------|
| T1110 | Brute Force |

### Detection Logic

This detection monitors Windows Security Event ID **4740** to identify accounts that become locked after exceeding the organization's configured authentication threshold.

Rather than monitoring every failed login individually, this detection highlights accounts that have already triggered the Windows account lockout policy, making them higher-priority candidates for investigation.

### Investigation Steps

- Identify the affected user account.
- Review the originating workstation.
- Correlate with preceding failed logon events (Event ID 4625).
- Determine whether privileged accounts were targeted.
- Verify whether the activity aligns with normal user behavior.

### Possible Impact

- Credential attacks
- Password spraying
- Brute-force attempts
- User account disruption
- Unauthorized access attempts

### Common False Positives

- Forgotten passwords
- Expired credentials
- Cached passwords
- Password synchronization issues
- Mobile devices using outdated credentials

### Analyst Recommendation

Correlate Event ID **4740** with failed authentication events (4625) and successful logons (4624) to determine whether the lockout resulted from malicious activity or normal user error.

📂 **Implementation**

```
authentication/account-lockout-detection/
```

---

# 2. After Hours Login Detection

## Objective

Identify successful user logins occurring outside approved business hours that may indicate compromised accounts, unauthorized access, or suspicious user activity.

### Threat Description

Threat actors frequently use stolen credentials during evenings, weekends, or holidays when legitimate user activity is reduced and security monitoring may be less active.

Monitoring authentication events outside normal working hours helps analysts identify suspicious access that could otherwise remain unnoticed.

### Windows Event

**Event ID 4624 — Successful Logon**

### MITRE ATT&CK

| Technique | Description |
|-----------|-------------|
| T1078 | Valid Accounts |

### Detection Logic

This detection monitors successful authentication events occurring outside predefined business hours.

Although after-hours logins are not always malicious, correlating these events with user roles, VPN activity, privileged access, and historical login behavior significantly improves investigation accuracy.

### Investigation Steps

- Verify whether the user normally works outside business hours.
- Review the source computer and IP address.
- Examine previous login history.
- Check VPN activity.
- Review recent password changes.
- Correlate with privileged account usage.

### Possible Impact

- Account compromise
- Unauthorized remote access
- Insider threats
- Privilege misuse

### Common False Positives

- Night shift employees
- IT administrators
- Scheduled maintenance
- Remote workers
- On-call engineers

### Analyst Recommendation

Always validate user schedules before escalating an alert. Correlate authentication activity with endpoint and network telemetry to determine whether the login was expected.

📂 **Implementation**

```
authentication/after-hours-login-detection/
```

---

# 3. Brute Force / Password Spray Detection

## Objective

Detect repeated failed authentication attempts originating from a single source that may indicate brute-force attacks or password spraying campaigns.

### Threat Description

Credential-based attacks remain one of the most common methods used to compromise Windows environments.

Traditional brute-force attacks repeatedly attempt passwords against a single account, while password spraying targets multiple accounts using a small set of commonly used passwords. Both techniques can eventually lead to unauthorized access if not detected early.

### Windows Event

**Event ID 4625 — Failed Logon**

### MITRE ATT&CK

| Technique | Description |
|-----------|-------------|
| T1110 | Brute Force |
| T1110.003 | Password Spraying |

### Detection Logic

This detection monitors failed authentication events and identifies repeated login failures originating from the same source within a defined time window.

The detection differentiates between traditional brute-force attacks and password spraying by analyzing both the number of failed logins and the number of unique user accounts targeted.

### Investigation Steps

- Review the source IP address.
- Identify targeted user accounts.
- Check whether any successful logins followed the failed attempts.
- Determine whether privileged accounts were targeted.
- Review authentication frequency.
- Correlate with firewall, VPN, and endpoint telemetry.

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
- Security testing

### Analyst Recommendation

Investigate repeated authentication failures immediately, particularly when multiple accounts are targeted from a single source. Early detection significantly reduces the likelihood of successful credential compromise.

📂 **Implementation**

```
authentication/brute-force-password-spray/
```

---

# 4. Failed Login Anomaly Detection

## Objective

Identify abnormal spikes in failed authentication attempts that deviate from normal authentication behavior.

### Threat Description

Not all credential attacks generate thousands of failed logins. Modern attackers frequently perform slow, distributed, or low-volume authentication attacks to avoid traditional threshold-based detections.

Monitoring authentication anomalies helps identify suspicious behavior that may otherwise remain undetected.

### Windows Event

**Event ID 4625 — Failed Logon**

### MITRE ATT&CK

| Technique | Description |
|-----------|-------------|
| T1110 | Brute Force |

### Detection Logic

This detection identifies unusual increases in failed authentication events within a specified time window.

Instead of relying solely on fixed thresholds, it highlights authentication activity that significantly exceeds normal behavior, allowing analysts to detect both high-volume and low-and-slow attacks.

### Investigation Steps

- Compare current activity with historical authentication trends.
- Identify affected systems and user accounts.
- Determine whether failures originate from one or multiple sources.
- Review successful authentication events occurring after the anomaly.
- Correlate with endpoint and network security logs.
- Investigate related security alerts.

### Possible Impact

- Credential attacks
- Password guessing
- Compromised endpoints
- Unauthorized authentication attempts
- Service disruption

### Common False Positives

- Organization-wide password resets
- Authentication service outages
- Bulk software deployments
- Active Directory synchronization issues
- Misconfigured applications

### Analyst Recommendation

Review authentication baselines regularly to minimize false positives. Correlating authentication anomalies with endpoint telemetry and user behavior provides greater confidence during investigations.

📂 **Implementation**

```
authentication/failed-login-anomaly/
```

---

# 5. Multiple Account Login Detection

## Objective

Detect systems that successfully authenticate multiple unique user accounts within a defined time window, which may indicate credential abuse, shared accounts, or lateral movement.

### Threat Description

After compromising a system, attackers frequently attempt to validate stolen credentials or move laterally by authenticating multiple user accounts from the same host.

Although this behavior may be legitimate on administrative systems, unexpected multi-account authentication from standard workstations should be investigated.

### Windows Event

**Event ID 4624 — Successful Logon**

### MITRE ATT&CK

| Technique | Description |
|-----------|-------------|
| T1078 | Valid Accounts |

### Detection Logic

This detection identifies hosts that successfully authenticate multiple unique user accounts during a specified time period.

By monitoring systems with an unusually high number of successful logins for different users, analysts can quickly identify potential credential misuse or unauthorized administrative activity.

### Investigation Steps

- Identify the originating computer.
- Review authenticated user accounts.
- Determine whether the system is an administrative workstation or jump server.
- Review recent authentication history.
- Investigate possible lateral movement.
- Correlate with endpoint and network security logs.

### Possible Impact

- Credential compromise
- Lateral movement
- Unauthorized access
- Privilege abuse
- Shared account misuse

### Common False Positives

- Shared workstations
- Domain Controllers
- Jump servers
- Helpdesk systems
- Administrative maintenance

### Analyst Recommendation

Unexpected multi-account authentication from user workstations should be investigated promptly. Correlate authentication events with endpoint telemetry to distinguish legitimate administrative activity from malicious credential abuse.

📂 **Implementation**

```
authentication/multi-account-login-detection/
```

---

# 6. NTLM Authentication Spike

## Objective

Detect abnormal spikes in NTLM authentication requests that may indicate password attacks, credential validation attempts, or authentication abuse.

### Threat Description

Although Kerberos is the preferred authentication protocol in Active Directory environments, NTLM is still widely used for legacy systems and certain applications.

Attackers often generate a large number of NTLM authentication requests while validating stolen credentials, conducting password spraying, or performing brute-force attacks.

Monitoring unusual increases in NTLM authentication activity helps analysts identify suspicious authentication behavior before successful compromise occurs.

### Windows Event

**Event ID 4776 — NTLM Credential Validation**

### MITRE ATT&CK

| Technique | Description |
|-----------|-------------|
| T1110 | Brute Force |

### Detection Logic

This detection monitors Windows Security Event ID **4776** and identifies systems generating an unusually high number of NTLM authentication requests within a specified time window.

Instead of investigating individual authentication events, analysts can quickly identify hosts producing abnormal NTLM activity that warrants further investigation.

### Investigation Steps

- Review the originating workstation.
- Identify targeted user accounts.
- Examine authentication frequency.
- Review authentication status codes.
- Check for successful logins following repeated NTLM failures.
- Correlate with endpoint detection and firewall logs.

### Possible Impact

- Password spraying
- Brute-force attacks
- Credential validation
- Unauthorized authentication attempts
- Legacy authentication abuse

### Common False Positives

- Legacy applications
- Authentication service restarts
- Scheduled administrative scripts
- Domain synchronization
- Bulk authentication activity

### Analyst Recommendation

Repeated NTLM authentication spikes should be investigated, especially when originating from user workstations or involving privileged accounts. Where possible, correlate with Kerberos authentication events and endpoint telemetry to determine whether the activity is expected.

📂 **Implementation**

```
authentication/ntlm-authentication-spike/
```

---

# Account Management

Windows account management events provide visibility into administrative actions that directly affect user identities. Monitoring these events helps identify persistence techniques, unauthorized account creation, and suspicious administrative activity.

---

# 7. Suspicious User Creation Detection

## Objective

Detect newly created Windows user accounts that may indicate unauthorized persistence, privilege escalation, or malicious administrative activity.

### Threat Description

Threat actors commonly create new user accounts after compromising a system to maintain persistent access. Unauthorized account creation enables attackers to regain access even after passwords are reset or compromised accounts are disabled.

Monitoring user account creation events allows analysts to identify suspicious administrative actions before attackers establish long-term persistence.

### Windows Event

**Event ID 4720 — A user account was created**

### MITRE ATT&CK

| Technique | Description |
|-----------|-------------|
| T1136 | Create Account |

### Detection Logic

This detection monitors Windows Security Event ID **4720** and identifies newly created user accounts.

Each account creation event should be reviewed to determine whether it aligns with approved onboarding processes or represents unauthorized administrative activity.

### Investigation Steps

- Verify whether the account creation was authorized.
- Identify the administrator responsible for creating the account.
- Review assigned group memberships.
- Check whether privileged groups were modified.
- Review additional administrative activity performed by the same account.
- Correlate with authentication and privilege escalation events.

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
- Test account creation

### Analyst Recommendation

Unexpected account creation events should always be investigated. Newly created privileged accounts require immediate attention due to their potential impact on the environment.

📂 **Implementation**

```
account-management/suspicious-user-creation/
```

---

# Privilege Escalation

Privilege escalation events provide insight into accounts receiving elevated permissions during authentication. Monitoring these events helps identify privileged account abuse, unauthorized administrative access, and suspicious elevation activity.

---

# 8. Special Privileges Assigned

## Objective

Detect successful logons where Windows assigns elevated privileges to a user account.

### Threat Description

Windows generates Event ID **4672** whenever an account logs on with administrative or highly privileged rights.

Although this event commonly occurs during legitimate administrator logins, unexpected privileged logons may indicate compromised administrator credentials, privilege escalation, or malicious administrative activity.

### Windows Event

**Event ID 4672 — Special privileges assigned to new logon**

### MITRE ATT&CK

| Technique | Description |
|-----------|-------------|
| T1078 | Valid Accounts |

### Detection Logic

This detection monitors Windows Security Event ID **4672** and identifies user accounts receiving elevated privileges during logon.

The detection assigns risk levels based on the frequency of privileged logons, helping analysts prioritize accounts requiring further investigation.

### Investigation Steps

- Verify whether the account normally has administrative privileges.
- Review the assigned privileges.
- Identify the source computer.
- Check login time and authentication history.
- Correlate with account management and authentication events.
- Investigate any related security alerts.

### Possible Impact

- Privilege escalation
- Administrative account abuse
- Credential compromise
- Unauthorized privileged access

### Common False Positives

- Domain Administrators
- System Administrators
- Backup Operators
- Scheduled maintenance
- Administrative service accounts

### Analyst Recommendation

Not every privileged logon is malicious. Focus investigations on unusual accounts, unexpected login locations, abnormal login times, or privileged activity that deviates from normal administrative behavior.

📂 **Implementation**

```
privilege-escalation/special-privileges-assigned/
```

---

# Lateral Movement

Lateral movement refers to techniques used by attackers to move from one compromised system to another after gaining initial access. Monitoring authentication events related to explicit credentials and Remote Desktop Protocol (RDP) sessions helps identify unauthorized remote access, credential abuse, and attacker movement within an enterprise environment.

---

# 9. Explicit Credential Logon

## Objective

Detect repeated use of explicit credentials that may indicate credential abuse, remote administration, or lateral movement.

### Threat Description

Windows generates Event ID **4648** whenever a process attempts to log on using explicit credentials instead of the currently logged-in user's credentials.

Although this behavior is common for legitimate administrative tools and Windows services, attackers frequently abuse explicit credentials to authenticate to remote systems after obtaining valid usernames and passwords.

Monitoring repeated explicit credential usage helps analysts identify suspicious authentication behavior that may indicate credential compromise or lateral movement.

### Windows Event

**Event ID 4648 — A logon was attempted using explicit credentials**

### MITRE ATT&CK

| Technique | Description |
|-----------|-------------|
| T1078 | Valid Accounts |
| T1021 | Remote Services |

### Detection Logic

This detection monitors Windows Security Event ID **4648** and identifies repeated explicit credential logons occurring within a defined time window.

The detection aggregates authentication attempts by user account, source IP address, target server, and initiating process to highlight systems generating unusually high explicit credential activity.

### Investigation Steps

- Identify the user account involved.
- Review the originating IP address.
- Verify the destination server.
- Examine the process initiating the authentication.
- Correlate with successful logon events (4624).
- Investigate additional administrative or remote access activity.

### Possible Impact

- Credential abuse
- Lateral movement
- Unauthorized remote administration
- Credential compromise
- Remote service abuse

### Common False Positives

- RunAs operations
- Administrative tools
- Scheduled administrative tasks
- Backup software
- Remote management utilities

### Analyst Recommendation

Repeated explicit credential usage from user workstations should be investigated, especially when targeting multiple systems or occurring outside normal administrative activities. Correlate with RDP, SMB, PowerShell, and authentication events to determine whether the activity is expected.

📂 **Implementation**

```
lateral-movement/explicit-credential-logon/
```

---

# 10. RDP Interactive Login

## Objective

Detect suspicious Remote Desktop Protocol (RDP) logons that may indicate unauthorized remote access or lateral movement.

### Threat Description

Remote Desktop Protocol (RDP) is widely used by administrators to remotely manage Windows systems.

Threat actors commonly abuse RDP after obtaining valid credentials to move laterally across an environment, establish persistence, or perform post-compromise activities.

Monitoring interactive RDP logons helps identify unusual remote access patterns that may indicate malicious activity.

### Windows Event

**Event ID 4624 — Successful Logon (Logon Type 10)**

### MITRE ATT&CK

| Technique | Description |
|-----------|-------------|
| T1021.001 | Remote Desktop Protocol |

### Detection Logic

This detection monitors successful RDP logons (Logon Type 10) and identifies users generating multiple RDP sessions or connecting from multiple source IP addresses within a defined time window.

The detection also extracts the actual logged-on user from the Windows Security Event using Splunk's `rex` command, providing more accurate investigation data when default field extraction is insufficient.

### Investigation Steps

- Identify the authenticated user.
- Review source IP addresses.
- Verify destination computer.
- Check login frequency and timing.
- Investigate additional remote access activity.
- Correlate with authentication, endpoint, and network security logs.

### Possible Impact

- Unauthorized remote access
- Lateral movement
- Credential compromise
- Administrative account abuse
- Persistence

### Common False Positives

- System administrators
- Helpdesk personnel
- Remote IT support
- Jump servers
- Scheduled maintenance

### Analyst Recommendation

Investigate RDP sessions originating from unusual locations, involving privileged accounts, or connecting to multiple systems within a short period. Correlating RDP activity with authentication events and endpoint telemetry significantly improves detection accuracy.

📂 **Implementation**

```
lateral-movement/rdp-interactive-login/
```
# SOC Investigation Workflow

The detections included in this repository are designed to support a structured Security Operations Center (SOC) investigation process.

```text
Windows Security Events
          │
          ▼
    Splunk Data Ingestion
          │
          ▼
    SPL Detection Rules
          │
          ▼
     Alert Generation
          │
          ▼
 Event Validation & Triage
          │
          ▼
 Threat Investigation
          │
          ▼
 Incident Response
          │
          ▼
Documentation & Continuous Improvement
```

This workflow demonstrates how raw Windows Security Events are transformed into actionable security alerts that enable analysts to investigate and respond to potential threats efficiently.

---

# Skills Demonstrated

## SIEM & Detection Engineering

- Splunk Enterprise
- Search Processing Language (SPL)
- Detection Engineering
- SIEM Content Development
- Alert Logic Design
- Risk-Based Alerting
- SPL Optimization
- Custom Field Extraction using `rex`

---

## Windows Security Monitoring

- Windows Security Event Analysis
- Authentication Monitoring
- Account Management Monitoring
- Privileged Logon Monitoring
- NTLM Authentication Monitoring
- Explicit Credential Monitoring
- RDP Activity Monitoring
- Windows Event Correlation

---

## Threat Detection

- Brute Force Detection
- Password Spraying Detection
- Authentication Anomaly Detection
- Account Lockout Monitoring
- NTLM Authentication Spike Detection
- Suspicious User Creation Detection
- Privileged Account Activity Monitoring
- Explicit Credential Usage Detection
- Remote Desktop (RDP) Monitoring
- Lateral Movement Detection

---

## Security Operations

- SOC Investigation Workflow
- Alert Triage
- Threat Hunting
- Detection Validation
- False Positive Reduction
- MITRE ATT&CK Mapping
- Blue Team Operations
- Security Event Correlation

---

# Learning Outcomes

Through this project I gained practical experience in:

- Writing efficient Splunk SPL queries
- Developing real-world SIEM detection rules
- Understanding Windows Security Events
- Building authentication and privilege escalation detections
- Detecting lateral movement techniques
- Using `rex` to extract custom fields from Windows Security Events
- Correlating Windows authentication events
- Mapping detections to the MITRE ATT&CK framework
- Investigating authentication-based attacks
- Reducing false positives through better detection logic
- Documenting security detections using industry-standard practices
- Building reusable SOC detection content
- Strengthening threat hunting methodologies

---

# Repository Structure

```text
splunk-detection-rules/
│
├── account-management/
│   └── suspicious-user-creation/
│
├── authentication/
│   ├── account-lockout-detection/
│   ├── after-hours-login-detection/
│   ├── brute-force-password-spray/
│   ├── failed-login-anomaly/
│   ├── multi-account-login-detection/
│   └── ntlm-authentication-spike/
│
├── lateral-movement/
│   ├── explicit-credential-logon/
│   └── rdp-interactive-login/
│
├── privilege-escalation/
│   └── special-privileges-assigned/
│
├── LICENSE
└── README.md
```

---

# Contributing

Contributions, improvements, and suggestions are welcome.

If you have ideas for new detection rules, optimizations, or additional Windows Security use cases, feel free to open an issue or submit a pull request.

---

# Disclaimer

This repository is intended for educational purposes, cybersecurity research, and personal lab environments.

The detection rules were developed to demonstrate Splunk SPL, Windows Security Event analysis, SIEM detection engineering, and SOC investigation methodologies.

No production logs, customer information, confidential data, proprietary security content, or sensitive organizational assets are included.

All screenshots, sample outputs, usernames, hostnames, IP addresses, and examples have been sanitized or anonymized to preserve privacy while maintaining technical accuracy.

---

# License

This project is licensed under the MIT License. See the **LICENSE** file for additional information.
