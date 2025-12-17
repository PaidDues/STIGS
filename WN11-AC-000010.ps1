#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Remediates DISA STIG WN11-AC-000010 by setting the local Account lockout threshold to 3 or fewer invalid logon attempts.

.DESCRIPTION
    This script enforces the STIG requirement by configuring the local Account Lockout Policy via the supported interface:
        net accounts /lockoutthreshold:<n>

    Per STIG intent:
      - The threshold must be 3 or fewer.
      - A value of 0 is NOT allowed (0 disables lockout).

    Note: On domain-joined systems, a domain GPO may override this local setting.

.PARAMETER LockoutThreshold
    The desired lockout threshold (1–3). Default is 3.

.NOTES
    Author          : Max Dues
    LinkedIn        : linkedin.com/in/mdues/
    GitHub          : github.com/PaidDues
    Date Created    : 2025-12-16
    Last Modified   : 2025-12-16
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AC-000010

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    Run as administrator.

.EXAMPLE
    .\WN11-AC-000010.ps1

.EXAMPLE
    .\WN11-AC-000010.ps1 -LockoutThreshold 2

.NOTES
    Verification: Run 'net accounts' and confirm "Lockout threshold" is 1–3.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1,3)]
    [int]$LockoutThreshold = 3
)

function Get-LockoutThreshold {
    $output = net accounts 2>$null
    if (-not $output) { return $null }

    $line = $output | Where-Object { $_ -match '^\s*Lockout threshold' } | Select-Object -First 1
    if (-not $line) { return $null }

    $m = [regex]::Match($line, 'Lockout threshold.*?:\s*(?<val>\d+)\s*$')
    if ($m.Success) { return [int]$m.Groups['val'].Value }

    return $null
}

try {
    # Check for administrator privileges
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This script requires administrator privileges. Please run as Administrator."
    }

    $before = Get-LockoutThreshold

    # Enforce
    net accounts "/lockoutthreshold:$LockoutThreshold" 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to set lockout threshold. Exit code: $LASTEXITCODE"
    }

    # Verify
    $after = Get-LockoutThreshold
    if ($null -eq $after) {
        Write-Warning "Applied requested setting, but could not parse verification output from 'net accounts'. Manually verify with: net accounts"
        exit 0
    }

    if ($after -eq $LockoutThreshold -and $after -ge 1 -and $after -le 3) {
        Write-Output "WN11-AC-000010 remediated successfully. Lockout threshold: $before -> $after"
        exit 0
    }

    Write-Warning "Remediation may not have applied as expected. Lockout threshold: $before -> $after (expected: $LockoutThreshold). A domain policy may be overriding local settings."
    exit 1
}
catch {
    Write-Error "Failed to remediate WN11-AC-000010. $($_.Exception.Message)"
    exit 1
}
