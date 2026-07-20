# Brute Force / Password Spray Detection

## Overview

This detection identifies repeated failed authentication attempts from a single source IP address. Such activity may indicate brute-force attacks or password spraying against Windows accounts.

---

## Detection Logic

The SPL query:

- Monitors Windows Security Event ID 4625 (failed logon).
- Groups events into 5-minute intervals.
- Counts failed login attempts from each source IP.
- Counts the number of unique user accounts targeted.
- Flags activity when:
  - 30 or more failed logins occur from a single IP, or
  - 20 or more failed logins target 3 or more different user accounts.

---

## Windows Event ID

| Event ID | Description |
|----------|-------------|
|4625|Failed account logon|

---

## MITRE ATT&CK

| Technique | Name |
|-----------|------|
|T1110|Brute Force|
|T1110.003|Password Spraying|

---

## Investigation Steps

1. Review the source IP address.
2. Identify targeted user accounts.
3. Check for successful logins after repeated failures.
4. Verify whether the IP is internal or external.
5. Block or isolate malicious sources if required.

---

## False Positives

- Users entering incorrect passwords repeatedly.
- Password synchronization issues.
- Automated scripts using outdated credentials.
- Misconfigured applications.
