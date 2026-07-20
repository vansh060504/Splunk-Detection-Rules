# Account Lockout Detection

## Overview

This detection identifies suspicious Windows account lockout activity using Windows Security Event ID **4740**.

Frequent account lockouts may indicate:

- Brute-force attacks
- Password spraying
- Repeated failed authentication attempts
- Misconfigured services using outdated credentials

---

## Detection Logic

The SPL query:

- Monitors Windows Security Event ID 4740.
- Groups events into 10-minute intervals.
- Counts lockout events for each user.
- Counts unique source computers generating lockouts.
- Assigns a risk level based on the number of lockouts.

---

## Windows Event ID

| Event ID | Description |
|----------|-------------|
|4740|A user account was locked out|

---

## MITRE ATT&CK

| Technique | Name |
|-----------|------|
|T1110|Brute Force|

---

## Detection Severity

- Medium Risk → 3–9 lockouts
- High Risk → 10 or more lockouts

---

## Investigation Steps

1. Identify the affected account.
2. Review the source system(s).
3. Check for repeated failed logons.
4. Verify whether credentials were compromised.
5. Determine whether the activity was malicious or user error.

---

## False Positives

- User repeatedly entering an incorrect password
- Expired cached credentials
- Service accounts with outdated passwords
- Scheduled tasks using old credentials
