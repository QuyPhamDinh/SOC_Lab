# Active Directory User & Group Provisioning Script

A reusable PowerShell script for creating Active Directory users and groups, managing group membership, and bulk-provisioning accounts from a CSV file.

## What it does

Provides four functions you can call individually or chain together:

- **`New-AcademyADUser`** — creates a single AD user account
- **`New-AcademyADGroup`** — creates a security or distribution group
- **`Add-AcademyADGroupMember`** — adds one or more users to a group
- **`New-AcademyADUsersFromCsv`** — bulk-creates users (and optionally assigns them to groups) from a CSV file

Each function checks whether the object already exists before creating it, so the script can be safely re-run without throwing errors on duplicates.

## Requirements

- Windows with the **ActiveDirectory PowerShell module** (part of RSAT — Remote Server Administration Tools)
- Permissions in AD sufficient to create users/groups and modify group membership in the target OU
- PowerShell 5.1 or later (compatible with Windows PowerShell and PowerShell 7+)

## Usage

### Dot-source the script to load the functions
```powershell
. .\New-AcademyADAccount.ps1
```

### Create a group
```powershell
New-AcademyADGroup -Name "HR_Team_A" -Category Security -Scope Global `
    -OUPath "OU=HR,DC=academy,DC=org"
```

### Create a user
```powershell
New-AcademyADUser -FirstName "Quy" -LastName "Pham" -SamAccountName "QPham" `
    -Domain "academy.org" -OUPath "OU=IT,DC=academy,DC=org" -ChangePasswordAtLogon
```
If no `-Password` is supplied, you'll be prompted securely at runtime.

### Add a user to a group
```powershell
Add-AcademyADGroupMember -GroupName "HR_Team_A" -Members "QPham"
```

### Bulk-create users from a CSV
```powershell
New-AcademyADUsersFromCsv -CsvPath ".\new_users.csv" -Domain "academy.org"
```

Expected CSV columns:

| FirstName | LastName | SamAccountName | OUPath | GroupName |
|---|---|---|---|---|
| Quy | Pham | QPham | OU=IT,DC=academy,DC=org | HR_Team_A |

`GroupName` is optional — leave it blank to create the user without adding them to a group.

## Design notes

- Passwords are handled as `SecureString` objects; the script never accepts or logs a plaintext password.
- All AD calls are wrapped in `try/catch` — failures are reported with `Write-Error` rather than halting the whole batch.
- Existence checks (`Get-ADUser` / `Get-ADGroup` / `Get-ADGroupMember`) make every function idempotent — safe to re-run against a partially completed batch.

## Known limitations

- Does not validate OU paths exist before attempting creation — an invalid `OUPath` will surface as a caught error per-object rather than being pre-checked.
- Does not enforce a domain password policy check before submission; a weak password will fail at the AD layer with the underlying error surfaced.
- No logging to file — output is console-only (`Write-Host` / `Write-Warning` / `Write-Error`). For audit trails, redirect output or add `Start-Transcript`.

## Author

phamdinhquy
