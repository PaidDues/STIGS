#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Implements DISA STIG WN11-AU-000505 by setting the Security event log maximum size to 1024000 KB (or greater).

.DESCRIPTION
    This script enforces the STIG requirement by configuring the following registry value:

        Hive      : HKEY_LOCAL_MACHINE (HKLM)
        Path      : SOFTWARE\Policies\Microsoft\Windows\EventLog\Security
        Value     : MaxSize
        Type      : REG_DWORD
        Required  : 1024000 (KB) minimum

    If the key path does not exist, it will be created. The script then verifies the final value.

.PARAMETER MaxSizeKB
    The maximum size (in KB) to set for the Security event log. Must be 1024000 or greater.

.NOTES
    Author          : Max Dues
    LinkedIn        : linkedin.com/in/mdues/
    GitHub          : github.com/PaidDues
    Date Created    : 2025-12-16
    Last Modified   : 2025-12-16
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AU-000505

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    Run as administrator.

.EXAMPLE
    .\WN11-AU-000505.ps1

.EXAMPLE
    .\WN11-AU-000505.ps1 -MaxSizeKB 1024000
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateRange(1024000, 4294967295)]
    [uint32]$MaxSizeKB = 1024000
)

$RegPath   = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'
$ValueName = 'MaxSize'
$Required  = $MaxSizeKB

# Ensure key exists
if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

# Set required value (DWORD)
New-ItemProperty -Path $RegPath -Name $ValueName -Value $Required -PropertyType DWord -Force | Out-Null

# Verify
$Actual = [uint32](Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction Stop).$ValueName
if ($Actual -ge $Required) {
    Write-Host "Compliant: $RegPath\$ValueName = $Actual (>= $Required)"
    exit 0
} else {
    Write-Warning "Non-compliant: $RegPath\$ValueName = $Actual (< $Required)"
    exit 1
}
