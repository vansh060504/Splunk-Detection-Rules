# After Hours Login Detection

## Overview

This detection identifies successful Windows logins occurring outside normal business hours (before 08:00 or after 20:00).

After-hours authentication may indicate:

- Unauthorized access
- Compromised credentials
- Suspicious administrator activity
- Insider threats

---

## Detection Logic

The SPL query:

- Monitors Windows Security Event ID 4624.
- Filters logins occurring before 08:00 or after 20:00.
- Groups activity into 15-minute windows.
- Counts login events and unique source IP addresses.
- Assigns a risk level based on login frequency.

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

---

## Investigation Steps

1. Verify whether the login occurred during an approved maintenance window.
2. Review the source IP address.
3. Check if MFA was used (if applicable).
4. Correlate with other authentication events.
5. Confirm whether the activity was expected.

---

## False Positives

- IT maintenance
- Scheduled backups
- Remote support sessions
- Users working outside normal hours
