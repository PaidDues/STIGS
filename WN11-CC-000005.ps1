#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Remediates DISA STIG WN11-CC-000005 by disabling camera access from the lock screen.

.DESCRIPTION
    This script enforces the STIG requirement by configuring the following registry value:

        Hive      : HKEY_LOCAL_MACHINE (HKLM)
        Path      : SOFTWARE\Policies\Microsoft\Windows\Personalization
        Value     : NoLockScreenCamera
        Type      : REG_DWORD
        Required  : 1

    If the key path does not exist, it will be created. The script then verifies the final value.

.NOTES
    Author          : Max Dues
    LinkedIn        : linkedin.com/in/mdues/
    GitHub          : github.com/PaidDues
    Date Created    : 2025-12-16
    Last Modified   : 2025-12-16
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000005

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    Run in an elevated PowerShell session.

.EXAMPLE
    .\WN11-CC-000005.ps1
#>

# -------------------------
# Configuration
# -------------------------
$regPath   = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
$valueName = "NoLockScreenCamera"
$valueData = 1

# -------------------------
# Remediation
# -------------------------
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

New-ItemProperty -Path $regPath -Name $valueName -PropertyType DWord -Value $valueData -Force | Out-Null

# -------------------------
# Verify
# -------------------------
$final = Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction Stop
if ($final.$valueName -eq $valueData) {
    Write-Host "Compliant: $valueName is set to $valueData at $regPath"
} else {
    Write-Warning "Non-compliant: $valueName is $($final.$valueName) (expected $valueData) at $regPath"
}
