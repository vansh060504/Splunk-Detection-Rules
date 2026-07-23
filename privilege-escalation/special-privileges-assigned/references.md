# References

## Detection Overview

This detection identifies Windows Security Event ID **4672 (Special privileges assigned to new logon)**. The event is generated whenever a new logon session is granted administrative or sensitive privileges such as SeDebugPrivilege, SeBackupPrivilege, SeRestorePrivilege, or SeTakeOwnershipPrivilege.

The rule filters out common Windows system accounts (SYSTEM, LOCAL SERVICE, NETWORK SERVICE, DWM-*, UMFD-*, ANONYMOUS LOGON) to reduce false positives and focuses on privileged activity performed by real user accounts.

## Detection Logic

- Monitors Windows Security Event ID **4672**
- Excludes built-in Windows system accounts
- Counts privileged logon events per user and computer
- Assigns a risk level based on the number of privileged logons:
  - **HIGH_PRIVILEGED_ACTIVITY** – 15 or more privileged logons
  - **MEDIUM_PRIVILEGED_ACTIVITY** – 5 to 14 privileged logons
  - **LOW_PRIVILEGED_ACTIVITY** – Fewer than 5 privileged logons

## MITRE ATT&CK

- **TA0004 – Privilege Escalation**
- **TA0003 – Persistence**
- **T1078 – Valid Accounts**
- **T1548 – Abuse Elevation Control Mechanism** (context dependent)

## Investigation Tips

- Verify whether the account is expected to have administrative privileges.
- Review Event ID 4624 (Successful Logon) associated with the same Logon ID.
- Determine whether the activity occurred during normal business hours.
- Identify the source workstation or server.
- Correlate with account creation, group membership changes, or privilege escalation events.
- Investigate repeated privileged logons from unusual systems or unexpected users.

## False Positives

Expected administrative activity may generate Event ID 4672, including:

- Domain Administrator logons
- Local Administrator logons
- Scheduled administrative tasks
- Patch management tools
- Backup software
- Endpoint management solutions
- Legitimate IT administration

The detection excludes common Windows service accounts to minimize false positives.

## References

- Microsoft Event ID 4672 Documentation
  https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4672

- Microsoft Windows Security Auditing
  https://learn.microsoft.com/windows/security/threat-protection/auditing/basic-audit-logon-events

- MITRE ATT&CK
  https://attack.mitre.org/

- Splunk Search Reference
  https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Searchcommands
