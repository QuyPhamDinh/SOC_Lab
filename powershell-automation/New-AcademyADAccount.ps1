<#
.SYNOPSIS
    Reusable functions for provisioning AD users, groups, and group
    memberships, plus bulk provisioning from a CSV file.

.NOTES
    Requires the ActiveDirectory module (RSAT) and appropriate permissions.
    Author: phamdinhquy
#>

Import-Module ActiveDirectory -ErrorAction Stop


function New-AcademyADUser {
    <#
    .SYNOPSIS
        Creates a single AD user account. Skips creation if the account
        already exists rather than throwing.

    .EXAMPLE
        New-AcademyADUser -FirstName "Quy" -LastName "Pham" `
            -SamAccountName "QPham" -Domain "academy.org" `
            -OUPath "OU=IT,DC=academy,DC=org"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FirstName,
        [Parameter(Mandatory)][string]$LastName,
        [Parameter(Mandatory)][string]$SamAccountName,
        [Parameter(Mandatory)][string]$Domain,
        [Parameter(Mandatory)][string]$OUPath,
        [System.Security.SecureString]$Password,
        [switch]$ChangePasswordAtLogon
    )

    $displayName = "$FirstName $LastName"
    $upn = "$SamAccountName@$Domain"

    # Skip instead of crashing if the account already exists
    if (Get-ADUser -Filter "SamAccountName -eq '$SamAccountName'" -ErrorAction SilentlyContinue) {
        Write-Warning "User '$SamAccountName' already exists — skipping."
        return
    }

    # Prompt securely at runtime if no password was supplied
    if (-not $Password) {
        $Password = Read-Host -Prompt "Enter password for $SamAccountName" -AsSecureString
    }

    try {
        New-ADUser `
            -Name $displayName `
            -GivenName $FirstName `
            -Surname $LastName `
            -SamAccountName $SamAccountName `
            -UserPrincipalName $upn `
            -Path $OUPath `
            -AccountPassword $Password `
            -Enabled $true `
            -ChangePasswordAtLogon:$ChangePasswordAtLogon.IsPresent `
            -ErrorAction Stop

        Write-Host "Created user: $SamAccountName ($upn)" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to create user '$SamAccountName': $_"
    }
}


function New-AcademyADGroup {
    <#
    .SYNOPSIS
        Creates a security or distribution group. Skips creation if the
        group already exists.

    .EXAMPLE
        New-AcademyADGroup -Name "HR_Team_A" -Category Security `
            -Scope Global -OUPath "OU=HR,DC=academy,DC=org"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [ValidateSet("Security", "Distribution")][string]$Category = "Security",
        [ValidateSet("DomainLocal", "Global", "Universal")][string]$Scope = "Global",
        [Parameter(Mandatory)][string]$OUPath
    )

    if (Get-ADGroup -Filter "Name -eq '$Name'" -ErrorAction SilentlyContinue) {
        Write-Warning "Group '$Name' already exists — skipping."
        return
    }

    try {
        New-ADGroup `
            -Name $Name `
            -GroupCategory $Category `
            -GroupScope $Scope `
            -Path $OUPath `
            -ErrorAction Stop

        Write-Host "Created group: $Name" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to create group '$Name': $_"
    }
}


function Add-AcademyADGroupMember {
    <#
    .SYNOPSIS
        Adds one or more users to a group. Skips members already present.

    .EXAMPLE
        Add-AcademyADGroupMember -GroupName "HR_Team_A" -Members "QPham"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$GroupName,
        [Parameter(Mandatory)][string[]]$Members
    )

    foreach ($member in $Members) {
        try {
            $existing = Get-ADGroupMember -Identity $GroupName -ErrorAction Stop |
                        Where-Object { $_.SamAccountName -eq $member }

            if ($existing) {
                Write-Warning "'$member' is already in '$GroupName' — skipping."
                continue
            }

            Add-ADGroupMember -Identity $GroupName -Members $member -ErrorAction Stop
            Write-Host "Added '$member' to '$GroupName'" -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to add '$member' to '$GroupName': $_"
        }
    }
}


function New-AcademyADUsersFromCsv {
    <#
    .SYNOPSIS
        Bulk-provisions users from a CSV file. Expected columns:
        FirstName, LastName, SamAccountName, OUPath, GroupName (optional)

    .EXAMPLE
        New-AcademyADUsersFromCsv -CsvPath ".\new_users.csv" -Domain "academy.org"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CsvPath,
        [Parameter(Mandatory)][string]$Domain
    )

    if (-not (Test-Path $CsvPath)) {
        Write-Error "CSV file not found: $CsvPath"
        return
    }

    $rows = Import-Csv -Path $CsvPath

    foreach ($row in $rows) {
        New-AcademyADUser `
            -FirstName $row.FirstName `
            -LastName $row.LastName `
            -SamAccountName $row.SamAccountName `
            -Domain $Domain `
            -OUPath $row.OUPath

        if ($row.GroupName) {
            Add-AcademyADGroupMember -GroupName $row.GroupName -Members $row.SamAccountName
        }
    }
}


# ---------------------------------------------------------------------------
# Example usage (uncomment to run directly instead of dot-sourcing elsewhere)
# ---------------------------------------------------------------------------

# New-AcademyADGroup -Name "HR_Team_A" -Category Security -Scope Global `
#     -OUPath "OU=HR,DC=academy,DC=org"

# New-AcademyADUser -FirstName "Quy" -LastName "Pham" -SamAccountName "QPham" `
#     -Domain "academy.org" -OUPath "OU=IT,DC=academy,DC=org" -ChangePasswordAtLogon

# Add-AcademyADGroupMember -GroupName "HR_Team_A" -Members "QPham"

# Bulk example (CSV with FirstName,LastName,SamAccountName,OUPath,GroupName):
# New-AcademyADUsersFromCsv -CsvPath ".\new_users.csv" -Domain "academy.org"
