# Failed Login Anomaly Detection

## Overview

This detection identifies abnormal spikes in failed login attempts for individual user accounts using statistical analysis.

Unlike fixed threshold-based detections, this rule compares current failed login activity against the historical average and standard deviation for each account.

---

## Detection Logic

The SPL query:

- Monitors Windows Security Event ID 4625 (Failed Logon).
- Groups failed logins into one-hour intervals.
- Calculates the average and standard deviation of failed logins per user.
- Flags activity when the current failed login count exceeds the calculated threshold.

Threshold Formula:

Threshold = Average Failed Logins + (2 × Standard Deviation)

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

---

## Investigation Steps

1. Identify the affected account.
2. Review the source IP address.
3. Compare with previous login history.
4. Check whether the account was later successfully authenticated.
5. Determine whether the activity represents a brute-force attempt or unusual user behavior.

---

## False Positives

- User repeatedly entering incorrect credentials.
- Password changes not updated on devices.
- Misconfigured scheduled tasks or applications.
- Temporary authentication issues.
