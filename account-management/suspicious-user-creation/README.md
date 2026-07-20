# Suspicious User Creation Detection

## Overview

This detection identifies unusual Windows user account creation activity by monitoring Windows Security Event ID **4720**.

Creating multiple user accounts in a short period may indicate unauthorized administrative activity, persistence techniques, or compromised administrator credentials.

---

## Detection Logic

The SPL query:

- Monitors Windows Security Event ID 4720.
- Groups account creation events into one-hour intervals.
- Counts the number of user accounts created.
- Counts unique user accounts created by the same administrator.
- Assigns a risk level based on the volume of account creation activity.

---

## Windows Event ID

| Event ID | Description |
|----------|-------------|
|4720|A user account was created|

---

## MITRE ATT&CK

| Technique | Name |
|-----------|------|
|T1136|Create Account|

---

## Detection Severity

- Medium Risk → 2–4 user accounts created
- High Risk → 5–9 user accounts created
- Critical Risk → 10 or more user accounts created

---

## Investigation Steps

1. Identify the administrator who created the accounts.
2. Verify whether account creation was authorized.
3. Review the source IP address.
4. Check whether the new accounts received elevated privileges.
5. Correlate with other administrative events.

---

## False Positives

- HR onboarding
- Bulk account provisioning
- Automated account creation scripts
- Active Directory synchronization
