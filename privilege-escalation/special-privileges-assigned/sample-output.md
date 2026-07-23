# Sample Output

| Time | ComputerName | Account_Name | privileged_logons | privileges | risk |
|------|--------------|--------------|------------------:|------------|---------------------------|
| 2026-07-23 09:10:00 | WIN-DC01 | Administrator | 18 | SeBackupPrivilege, SeRestorePrivilege, SeDebugPrivilege, SeTakeOwnershipPrivilege | HIGH_PRIVILEGED_ACTIVITY |
| 2026-07-23 08:45:18 | WIN-SRV02 | SOCAdmin | 8 | SeBackupPrivilege, SeDebugPrivilege | MEDIUM_PRIVILEGED_ACTIVITY |
| 2026-07-23 07:52:46 | WIN-CLIENT05 | Helpdesk01 | 2 | SeChangeNotifyPrivilege, SeDebugPrivilege | LOW_PRIVILEGED_ACTIVITY |

## Interpretation

- **Administrator** logged on with administrative privileges 18 times on **WIN-DC01**. This exceeds the high-risk threshold and should be investigated to confirm expected administrative activity.

- **SOCAdmin** received privileged access 8 times on **WIN-SRV02**. Verify whether these logons correspond to authorized maintenance or administrative tasks.

- **Helpdesk01** received privileged access twice on **WIN-CLIENT05**. While categorized as low risk, the activity should still be reviewed if it occurred outside normal administrative operations.
