# Monthly access review runbook

One afternoon at the start of each month: export, run, work the critical findings the same day, and take the pack to the IAM service review. The tool only reads exports; accounts, groups, roles and vault entries are changed in their own consoles, through the normal change or request process.

## Day 1: export (30 minutes)

1. Active Directory and Entra ID (read-only, from a machine with RSAT and the Microsoft Graph PowerShell SDK):
   ```powershell
   .\scripts\Export-AccessReviewData.ps1 -OutputFolder .\data -EntitlementCatalogue .\data\entitlements.csv -ForestRootServer dc01.corp.contoso.com
   ```
   The first run asks an administrator to consent to User.Read.All, AuditLog.Read.All, RoleManagement.Read.Directory and GroupMember.Read.All.
2. HR: the roster with leavers of the last three months, start dates, movement dates and the previous department, as `hr.csv`.
3. PAM: the account list of the vault (safe, platform, last change, automatic management) as `pam-accounts.csv`.
4. The service account register and the results of the running recertification campaign, as `service-register.csv` and `recert-results.csv`.
5. Check `settings.json`: `as_of`, `period_start`, the break-glass accounts and the approved Tier 0 list.

## Day 1: run and fix the critical ones (2 hours)

```bash
python -m iamreview review data/ --title "Access review · September 2026"
```

| Order | What | Output | Who |
|---|---|---|---|
| 1 | Leavers with an enabled account, admin accounts first | `leavers.csv`, LVR-01 | IAM operations, same day |
| 2 | Standing Global Administrator, Tier 0 members not approved, privileged without MFA | `privileged.csv`, PRV-01..03 | Infrastructure lead, same day |
| 3 | Revokes not actioned where the user is still a member | `recert.csv` (status `revoke pending`) | IAM operations |
| 4 | Service accounts whose owner left, or signing in interactively | `service-accounts.csv` | IAM operations with the application owner |
| 5 | Orphans with sensitive access | `orphans.csv` | IAM operations |
| 6 | Vaulted passwords overdue, admin accounts outside the vault | `privileged.csv` (PAM vault rows) | PAM administrator |

For every account disabled: write the ticket number in `actions.csv`, and for a leaver who signed in after the end date, open a security incident before anything else.

## The monthly IAM service review (30 minutes)

| Minutes | Topic | From the pack (`access-review.md`) |
|---|---|---|
| 5 | Overall status and the status per area | Summary |
| 10 | Controls not effective and why: the leaver feed, the mover process, PIM, the vault | Controls tested, Exceptions by control |
| 5 | Recertification: completion, overdue reviewers, revokes, rubber-stamping | Recertification by reviewer |
| 5 | Actions: owner and date for each | Actions |
| 5 | Trend against last month, accepted risks, sign-off | Notes for the auditor, Sign-off |

Keep each month's output folder (pack, CSVs and the exports) for the audit trail. The pack states the sources, the record counts, the policy parameters and every exception, which is what an auditor asks for when testing access controls.

## How to read it

- **A leaver's account that is enabled is a finding even if nobody used it.** If someone did sign in after the end date, it is an incident.
- **Admin accounts leave with their owner.** They carry the owner's employee ID; the tool finds them with the leaver.
- **A mover keeps two jobs' access until someone removes the old one.** The HR movement date starts the clock, not the next campaign.
- **Standing is the exception, eligible is the rule.** Only the break-glass accounts should hold Global Administrator permanently, and their sign-ins should be watched.
- **An approve in seconds is not a review.** The rubber-stamp check is a signal to talk to the reviewer, not proof; show them last sign-in and department next time.
- **lastLogonTimestamp lags.** Up to 14 days behind the real last logon: use it for the 90-day rule, not to prove a leaver did not log on yesterday (use the DC security log or the Entra ID sign-in log for that).
