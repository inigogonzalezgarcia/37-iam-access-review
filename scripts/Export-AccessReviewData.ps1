<#
.SYNOPSIS
    Read-only export of Active Directory users, Entra ID users with sign-in activity, group memberships and Entra ID role assignments
    (active and PIM eligible), written as the CSV files that iamreview reads.

.DESCRIPTION
    Only Get- cmdlets. Nothing is created, changed or deleted in Active Directory or Entra ID.

    Active Directory (ActiveDirectory module, RSAT), any domain user can read these attributes:
      - ad-users.csv:     Get-ADUser -Filter * -Properties employeeID, lastLogonTimestamp (LastLogonDate), pwdLastSet (PasswordLastSet),
                          PasswordNeverExpires, whenCreated, memberOf, Description, userPrincipalName.
                          LastLogonDate is lastLogonTimestamp, which replicates with a lag of up to 14 days: good enough for 90-day inactivity.
      - memberships.csv:  Get-ADGroupMember -Recursive for every group of the entitlement catalogue and every Tier 0 group (nested members
                          included). Enterprise Admins and Schema Admins live in the forest root domain: pass -ForestRootServer.
                          Groups over the Active Directory Web Services limit (5,000 members by default) are read with an LDAP_MATCHING_RULE_IN_CHAIN
                          query instead.

    Entra ID (Microsoft Graph PowerShell SDK: Microsoft.Graph.Users, Microsoft.Graph.Groups, Microsoft.Graph.Reports,
    Microsoft.Graph.Identity.Governance), delegated read permissions, consented once by an administrator:
      - User.Read.All                 users, employeeId, onPremisesSamAccountName, guests and their sponsors (Get-MgUser, Get-MgUserSponsor)
      - AuditLog.Read.All             signInActivity on the users and the MFA registration report
                                      (Get-MgReportAuthenticationMethodUserRegistrationDetail). signInActivity needs Entra ID P1 or P2.
      - RoleManagement.Read.Directory role definitions, active role assignment instances (Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance:
                                      AssignmentType Assigned = standing, Activated = just-in-time through PIM) and eligibilities
                                      (Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance, PIM needs Entra ID P2)
      - GroupMember.Read.All          members of the cloud groups in the catalogue (Get-MgGroupTransitiveMember); only with -EntitlementCatalogue
    The account that consents needs a role that can grant them (Privileged Role Administrator or Global Administrator); the account that runs
    the export only needs the delegated permissions and a reader role such as Global Reader.

    Not exported here, because they live in other tools: hr.csv (HR system report), entitlements.csv (your entitlement catalogue),
    pam-accounts.csv (the PAM vault's account list), service-register.csv (your service account register) and recert-results.csv (the
    campaign results). See docs/data-format.md for their columns.

.PARAMETER OutputFolder
    Where the CSV files are written (created if missing).

.PARAMETER EntitlementCatalogue
    entitlements.csv. Its Group column says which groups to export members of; without it only the Tier 0 groups are exported.

.EXAMPLE
    .\scripts\Export-AccessReviewData.ps1 -OutputFolder .\data -EntitlementCatalogue .\data\entitlements.csv -ForestRootServer dc01.corp.contoso.com

.EXAMPLE
    # Active Directory only (no Graph connection)
    .\scripts\Export-AccessReviewData.ps1 -OutputFolder .\data -SkipEntra
#>
[CmdletBinding()]
param(
    [string] $OutputFolder = '.\data',
    [string] $EntitlementCatalogue = '',
    [string] $SearchBase = '',
    [string] $Server = '',
    [string] $ForestRootServer = '',
    [string[]] $Tier0Groups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators', 'Account Operators', 'Backup Operators',
                                'Server Operators', 'Print Operators'),
    [string] $TenantId = '',
    [switch] $SkipAD,
    [switch] $SkipEntra,
    [switch] $SkipSponsors,
    [switch] $SkipMfa
)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $OutputFolder | Out-Null

function Write-Out([object[]] $rows, [string] $name) {
    $path = Join-Path $OutputFolder $name
    $rows | Export-Csv -Path $path -NoTypeInformation -Encoding utf8
    Write-Host ("{0,6} rows -> {1}" -f @($rows).Count, $path)
}
function Fmt($d) { if ($d) { ([datetime] $d).ToString('yyyy-MM-dd HH:mm:ss') } else { '' } }
function Iso($d) { if ($d) { ([datetime] $d).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' } }

$catalogueGroups = @()
if ($EntitlementCatalogue) {
    $catalogueGroups = @(Import-Csv $EntitlementCatalogue | ForEach-Object { $_.Group } | Where-Object { $_ } | Select-Object -Unique)
}
$wanted = @($catalogueGroups + $Tier0Groups | Select-Object -Unique)
$memberships = [System.Collections.Generic.List[object]]::new()
$foundInAD = @{}

# ------------------------------------------------------------------ Active Directory
if (-not $SkipAD) {
    Import-Module ActiveDirectory
    $ad = @{}
    if ($Server) { $ad.Server = $Server }
    $search = @{} + $ad
    if ($SearchBase) { $search.SearchBase = $SearchBase }
    $props = 'employeeID', 'LastLogonDate', 'PasswordLastSet', 'PasswordNeverExpires', 'whenCreated', 'memberOf', 'Description', 'userPrincipalName'
    $users = Get-ADUser -Filter * -Properties $props @search
    Write-Out ($users | ForEach-Object { [pscustomobject] @{
        'SamAccountName' = $_.SamAccountName; 'EmployeeID' = $_.employeeID; 'Enabled' = $_.Enabled; 'LastLogonDate' = (Fmt $_.LastLogonDate)
        'PasswordLastSet' = (Fmt $_.PasswordLastSet); 'PasswordNeverExpires' = $_.PasswordNeverExpires; 'whenCreated' = (Fmt $_.whenCreated)
        'MemberOf' = ($_.memberOf -join ';'); 'Description' = $_.Description; 'UserPrincipalName' = $_.UserPrincipalName; 'Name' = $_.Name } }) 'ad-users.csv'

    foreach ($g in $wanted) {
        $gArgs = @{} + $ad
        if ($ForestRootServer -and $g -in @('Enterprise Admins', 'Schema Admins')) { $gArgs.Server = $ForestRootServer }
        try { $group = Get-ADGroup -Identity $g @gArgs } catch { continue }
        $foundInAD[$g] = $true
        try {
            $members = @(Get-ADGroupMember -Identity $group -Recursive @gArgs | Where-Object { $_.objectClass -eq 'user' } |
                         ForEach-Object { $_.SamAccountName })
        } catch {
            # over the ADWS member limit: transitive membership through the in-chain matching rule
            $members = @(Get-ADUser -LDAPFilter "(memberOf:1.2.840.113556.1.4.1941:=$($group.DistinguishedName))" @gArgs | ForEach-Object { $_.SamAccountName })
        }
        foreach ($m in $members) { $memberships.Add([pscustomobject] @{ 'Group' = $g; 'Member' = $m; 'Source' = 'AD' }) }
    }
}

# ------------------------------------------------------------------ Entra ID
if (-not $SkipEntra) {
    $scopes = @('User.Read.All', 'AuditLog.Read.All', 'RoleManagement.Read.Directory')
    if ($catalogueGroups.Count) { $scopes += 'GroupMember.Read.All' }
    $connect = @{ Scopes = $scopes; NoWelcome = $true }
    if ($TenantId) { $connect.TenantId = $TenantId }
    Connect-MgGraph @connect

    $select = 'id', 'userPrincipalName', 'displayName', 'employeeId', 'accountEnabled', 'userType', 'createdDateTime', 'onPremisesSamAccountName',
              'signInActivity'
    $mg = @(Get-MgUser -All -Property $select -PageSize 500)
    $byId = @{}
    foreach ($u in $mg) { $byId[$u.Id] = $u.UserPrincipalName }

    $mfa = @{}
    if (-not $SkipMfa) {
        Get-MgReportAuthenticationMethodUserRegistrationDetail -All | ForEach-Object { $mfa[$_.Id] = $_.IsMfaRegistered }
    }
    Write-Out ($mg | ForEach-Object {
        $u = $_
        $sponsors = ''
        if (-not $SkipSponsors -and $u.UserType -eq 'Guest') {
            $sponsors = (@(Get-MgUserSponsor -UserId $u.Id -All) | ForEach-Object {
                if ($_.AdditionalProperties['userPrincipalName']) { $_.AdditionalProperties['userPrincipalName'] } else { $_.AdditionalProperties['displayName'] } }) -join ';'
        }
        [pscustomobject] @{
            'UserPrincipalName' = $u.UserPrincipalName; 'EmployeeId' = $u.EmployeeId; 'AccountEnabled' = $u.AccountEnabled; 'UserType' = $u.UserType
            'CreatedDateTime' = (Iso $u.CreatedDateTime); 'LastSignInDateTime' = (Iso $u.SignInActivity.LastSignInDateTime)
            'LastSuccessfulSignInDateTime' = (Iso $u.SignInActivity.LastSuccessfulSignInDateTime)
            'LastNonInteractiveSignInDateTime' = (Iso $u.SignInActivity.LastNonInteractiveSignInDateTime)
            'OnPremisesSamAccountName' = $u.OnPremisesSamAccountName; 'Sponsors' = $sponsors
            'IsMfaRegistered' = $(if ($mfa.ContainsKey($u.Id)) { $mfa[$u.Id] } else { '' }); 'DisplayName' = $u.DisplayName } }) 'entra-users.csv'

    # roles: active instances (standing or activated) and eligibilities
    $defs = @{}
    Get-MgRoleManagementDirectoryRoleDefinition -All | ForEach-Object { $defs[$_.Id] = $_.DisplayName }
    $principal = { param($id) if ($byId.ContainsKey($id)) { $byId[$id] } else { $id } }
    $active = Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -All | ForEach-Object { [pscustomobject] @{
        'Principal' = (& $principal $_.PrincipalId); 'Role' = $defs[$_.RoleDefinitionId]; 'State' = 'Active'; 'AssignmentType' = $_.AssignmentType
        'StartDateTime' = (Iso $_.StartDateTime); 'EndDateTime' = (Iso $_.EndDateTime); 'MemberType' = $_.MemberType; 'DirectoryScopeId' = $_.DirectoryScopeId } }
    $eligible = Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -All | ForEach-Object { [pscustomobject] @{
        'Principal' = (& $principal $_.PrincipalId); 'Role' = $defs[$_.RoleDefinitionId]; 'State' = 'Eligible'; 'AssignmentType' = ''
        'StartDateTime' = (Iso $_.StartDateTime); 'EndDateTime' = (Iso $_.EndDateTime); 'MemberType' = $_.MemberType; 'DirectoryScopeId' = $_.DirectoryScopeId } }
    Write-Out (@($active) + @($eligible)) 'privileged-roles.csv'

    # cloud groups of the catalogue (the ones not found in Active Directory)
    foreach ($g in $catalogueGroups | Where-Object { -not $foundInAD[$_] }) {
        $grp = Get-MgGroup -Filter "displayName eq '$($g -replace "'", "''")'" -Property 'id,displayName' | Select-Object -First 1
        if (-not $grp) { Write-Warning "group not found in AD or Entra ID: $g"; continue }
        Get-MgGroupTransitiveMember -GroupId $grp.Id -All | Where-Object { $_.AdditionalProperties['@odata.type'] -eq '#microsoft.graph.user' } |
            ForEach-Object { $memberships.Add([pscustomobject] @{ 'Group' = $g; 'Member' = $_.AdditionalProperties['userPrincipalName']; 'Source' = 'Entra' }) }
    }
}

Write-Out $memberships 'memberships.csv'
Write-Host "Add hr.csv, entitlements.csv, pam-accounts.csv, service-register.csv, recert-results.csv and settings.json; then run:"
Write-Host "  python -m iamreview review $OutputFolder"
