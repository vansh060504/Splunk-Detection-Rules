# Multiple Account Login Detection

## Overview

This detection identifies a single source IP address successfully authenticating multiple user accounts within a one-hour period.

This behavior may indicate:

- Password spraying
- Shared credentials
- Compromised systems
- Unauthorized administrative activity

---

## Detection Logic

The SPL query:

- Monitors Windows Security Event ID 4624 (Successful Logon).
- Excludes computer accounts and anonymous logons.
- Groups successful logons into one-hour intervals.
- Counts the number of unique user accounts authenticating from each source IP.
- Flags source IPs authenticating five or more unique user accounts.

---

## Windows Event ID

| Event ID | Description |
|----------|-------------|
|4624|Successful account logon|

---

## MITRE ATT&CK

| Technique | Name |
|-----------|------|
|T1078|Valid Accounts|
|T1110.003|Password Spraying|

---

## Investigation Steps

1. Review the source IP address.
2. Verify whether the system is a shared workstation or jump server.
3. Identify the affected user accounts.
4. Check authentication history for unusual behavior.
5. Correlate with failed logon events and privilege escalation activity.

---

## False Positives

- Shared administrative workstations.
- Jump servers.
- Terminal servers.
- Helpdesk systems.
- Domain Controllers.
