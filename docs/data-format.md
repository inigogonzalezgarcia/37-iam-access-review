# Data format

Put the files in one folder and run `python -m iamreview review <folder>`. `hr.csv` is required, and at least one of `ad-users.csv` and `entra-users.csv`; every other file adds its checks when present. Comma, semicolon or tab separated (the header line decides), UTF-8. Column names are matched loosely (case, accents, dots and punctuation are ignored), and the common alternatives below, including the names that `Get-ADUser`, `Get-MgUser` and Spanish HR reports use, are accepted.

`scripts/Export-AccessReviewData.ps1` writes `ad-users.csv`, `entra-users.csv`, `memberships.csv` and `privileged-roles.csv`. The other files come from the HR system, the PAM vault, the service account register and the recertification tool.

Dates: `YYYY-MM-DD`, `YYYY-MM-DD HH:MM[:SS]`, ISO 8601 with `Z` or an offset (kept as written: Graph returns UTC), `DD/MM/YYYY [HH:MM]`, raw Active Directory FILETIME values (`lastLogonTimestamp`, `pwdLastSet`) and Unix seconds. `0`, `never` and empty mean no date.

## How accounts are linked to people

- An account belongs to the person whose **employee ID** it carries (`employeeID` in AD, `employeeId` in Entra ID).
- A synced Entra ID user (with `onPremisesSamAccountName`) is the same identity as its AD account: it inherits the employee ID, its sign-ins count for the AD account's inactivity, and it is judged once (on the AD side) for orphans and inactivity.
- Admin accounts (`admin_account_pattern`, by default `adm-…`) carry the employee ID of their owner, so a leaver's admin account is found with the leaver.
- Service accounts are the ones in the register, plus anything matching `service_account_pattern` (`svc-…`); unregistered ones are reported as orphans.
- Break-glass accounts are listed in `break_glass` and only reported for information.

## hr.csv (required)

One row per person, leavers included (at least those of the last months).

| Column | Also accepted | Notes |
|---|---|---|
| Employee ID | employeeid, employee number, worker id, número empleado | The key that links accounts to people |
| Name | full name, display name, nombre | |
| Department | dept, business unit, departamento | Compared with the department tag of each entitlement (movers) |
| Manager ID | manager, line manager, reports to, responsable | Employee ID (or name) of the manager; joiners without one are flagged |
| Status | employment status, worker status, estado | `Terminated`, `Leaver`, `Withdrawn`, `Baja`… mark a leaver even without an end date |
| Start date | hire date, fecha alta | Joiners: from `joiner_window_days` before the review, future starters included |
| End date | termination date, last day, fecha baja | A past end date makes a leaver |
| Last movement date | transfer date, fecha movimiento | Movers |
| Previous department | from department, departamento anterior | Optional: limits the mover check to the entitlements of that department |
| Cost centre, Location | cost center, centro coste, office, ubicación | For the CSVs |

## ad-users.csv

`Get-ADUser -Filter * -Properties employeeID, LastLogonDate, PasswordLastSet, PasswordNeverExpires, whenCreated, memberOf, Description, userPrincipalName`.

| Column | Also accepted | Notes |
|---|---|---|
| SamAccountName | sam, logon name | |
| EmployeeID | employee id, employeenumber | |
| Enabled | | `True` / `False` |
| LastLogonDate | lastLogonTimestamp | Replicated attribute, up to 14 days behind the real last logon: fine for a 90-day rule, not for "yesterday" |
| PasswordLastSet | pwdLastSet | |
| PasswordNeverExpires | | Flagged on human and admin accounts unless the account is in the vault with automatic rotation |
| whenCreated | created | Accounts that never signed in count as inactive from this date |
| MemberOf | groups | Distinguished names or names separated by `;` (direct groups; nested membership comes from `memberships.csv`) |
| Description, UserPrincipalName, Name | | |

## entra-users.csv

`Get-MgUser -All -Property id, userPrincipalName, displayName, employeeId, accountEnabled, userType, createdDateTime, onPremisesSamAccountName, signInActivity` (User.Read.All and AuditLog.Read.All; sign-in activity needs Entra ID P1 or P2), the sponsors of each guest (`Get-MgUserSponsor`) and `isMfaRegistered` from `Get-MgReportAuthenticationMethodUserRegistrationDetail` (AuditLog.Read.All).

| Column | Also accepted | Notes |
|---|---|---|
| UserPrincipalName | upn | |
| EmployeeId | | Empty on synced users is fine: the AD account gives it |
| AccountEnabled | enabled | |
| UserType | | `Member` or `Guest` |
| CreatedDateTime | created | |
| LastSignInDateTime | signInActivity.lastSignInDateTime | Last **interactive** sign-in attempt: used for service accounts that should not sign in interactively |
| LastSuccessfulSignInDateTime, LastNonInteractiveSignInDateTime | | The most recent of the three is the account's last activity |
| OnPremisesSamAccountName | | Links the user to its AD account |
| Sponsors | sponsor | UPNs or names separated by `;`; guests without one are flagged |
| IsMfaRegistered | mfa registered | Empty means unknown, and the MFA check is skipped |
| DisplayName | | |

## memberships.csv

Members of the catalogue groups and the Tier 0 groups, nested members included (`Get-ADGroupMember -Recursive`, `Get-MgGroupTransitiveMember`).

| Column | Also accepted | Notes |
|---|---|---|
| Group | group name, entitlement | Name or distinguished name |
| Member | samaccountname, userprincipalname, account | sAMAccountName for AD, UPN for Entra ID |
| Source | directory | `AD` or `Entra` (information) |
| Added | granted on | Optional: a grant before the person's start date is flagged for joiners |

## entitlements.csv (the catalogue)

| Column | Also accepted | Notes |
|---|---|---|
| Group | entitlement | Must match the group name in the memberships |
| Application | app, system | |
| Tier | sensitivity tier, criticality | `0` (control plane: Domain Admins and similar), `1` (high), `2` (medium), `3` (low); words High/Medium/Low work too |
| Owner | entitlement owner, approver | |
| Department | department tag | Department(s) the access belongs to, separated by `;`; empty = everybody. A person in another department after a move keeps it only during the grace |
| Recertify every days | recert days, requires recertification every n days | Empty or 0: not recertified (baseline groups) |
| Privileged | admin | `Yes` makes the group Tier 0 as well |
| Last certified | last review | Date of the last review outside the campaign file; the latest decision in `recert-results.csv` counts too |

## privileged-roles.csv

Active role assignment instances (`Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance`) and eligibilities (`Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance`), RoleManagement.Read.Directory.

| Column | Also accepted | Notes |
|---|---|---|
| Principal | userprincipalname, upn | UPN; groups and service principals appear as their object ID |
| Role | role name, role definition | Display name of the role definition |
| State | assignment | `Active` or `Eligible` |
| AssignmentType | assignment type | Active only: `Assigned` (standing, directly or through PIM as active) or `Activated` (just-in-time) |
| StartDateTime, EndDateTime | start, end | An active assignment without an end is permanent |
| MemberType, DirectoryScopeId | member type, scope | `Direct`, `Group` or `Inherited`; `/` is tenant-wide |

## pam-accounts.csv

The vault's account list. In CyberArk, the account list of the PVWA or the Accounts REST API give the safe, platform, user name, address, whether automatic management is enabled and when the secret was last changed; last used comes from the account activity.

| Column | Also accepted | Notes |
|---|---|---|
| Account | username, user name | Matched to AD and Entra ID accounts by name (a UPN or `DOMAIN\name` also matches) |
| Safe, Platform, Address | safeName, platformId, domain | `pam_rotation_by_platform` can set a policy per platform |
| Last password change | lastModifiedTime, last changed | Older than the policy: warning; more than twice, or none: critical |
| Last used | last accessed | Information |
| Owner | | |
| Automatic management | automaticManagementEnabled, managed | `No` is a warning: nobody rotates it |

## service-register.csv

| Column | Also accepted | Notes |
|---|---|---|
| Account | samaccountname, service account | |
| Owner | business owner, responsable | Employee ID or name of a person; empty, unknown or a leaver is flagged |
| Purpose | description, uso | |
| Interactive sign-in allowed | interactive | `Yes` is a warning; an interactive sign-in when it says `No` is critical |
| Directory | source | |

## recert-results.csv

One row per item of the campaign, from your recertification tool or spreadsheet.

| Column | Also accepted | Notes |
|---|---|---|
| Campaign | review | |
| Item ID | item, id | |
| Group, User | entitlement, access · member, account | The user is checked against the current memberships ("still a member") |
| Reviewer | reviewed by, decided by | |
| Decision | result, outcome | Approve / approved / keep / certify, or revoke / remove / deny; empty = no decision |
| Decided on | decision date, reviewed on | With seconds if you have them: the rubber-stamp check measures minutes |
| Due date | due, campaign end | No decision after this date is overdue |
| Removed on | remediated, fulfilled | A revoke without it after `revoke_sla_days` is not actioned |

## settings.json

| Key | Default | What |
|---|---|---|
| `organisation`, `as_of`, `period_start` | | Name for the reports; review time (otherwise now); first day of the period reviewed |
| `leaver_grace_days` | 1 | Days after the end date to disable the accounts |
| `mover_grace_days` | 14 | Days after a move to keep the old department's access |
| `joiner_window_days` | 30 | Starters from this many days before the review, and future starters |
| `inactive_days`, `guest_inactive_days`, `privileged_inactive_days` | 90, 90, 45 | Inactivity thresholds |
| `pim_roles`, `critical_roles` | Global Administrator and the main admin roles · Global, Privileged Role and Privileged Authentication Administrator | Roles that must be eligible, not standing · standing ones that are critical |
| `break_glass` | [] | Emergency accounts (UPN or name) |
| `tier0_groups`, `approved_tier0` | Domain/Enterprise/Schema Admins, Administrators, the Operators groups · [] | Tier 0 groups and the accounts approved to be in them |
| `admin_account_pattern`, `service_account_pattern` | `^(adm\|admin)[-_.]`, `^(svc\|sa)[-_.]` | Regular expressions on the account name |
| `pam_rotation_days`, `pam_rotation_by_platform` | 90, {} | Password rotation policy |
| `vault_required` | tier0, admin, break_glass | Accounts that must be in the vault |
| `recert_default_days` | 0 | Frequency for catalogue rows without one |
| `revoke_sla_days` | 5 | Days to remove access after a revoke |
| `rubber_min_items`, `rubber_max_minutes`, `rubber_approve_pct` | 50, 10, 100 | A reviewer with at least N decisions, all approved, in under M minutes |
| `owners` | | Owner per area: leavers, movers, joiners, accounts, privileged, pam, service, guests, recert |
