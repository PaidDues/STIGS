#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Remediates DISA STIG WN11-CC-000190 by disabling AutoPlay for all drives.

.DESCRIPTION
    This script enforces the STIG requirement by setting the following registry value:

        Hive      : HKEY_LOCAL_MACHINE (HKLM)
        Path      : SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer
        Value     : NoDriveTypeAutoRun
        Type      : REG_DWORD
        Required  : 0x000000FF (255)

    If the key path does not exist, it will be created. The script then verifies the final value.

.NOTES
    Author          : Max Dues
    LinkedIn        : linkedin.com/in/mdues/
    GitHub          : github.com/PaidDues
    Date Created    : 2025-12-16
    Last Modified   : 2025-12-16
    Version         : 1.0
    STIG-ID         : WN11-CC-000190
    STIG-Title      : AutoPlay must be turned off (enforced via NoDriveTypeAutoRun = 0xFF)

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. :

.EXAMPLE
    .\WN11-CC-000190.ps1
#>

$RegPath   = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
$ValueName = 'NoDriveTypeAutoRun'
$ValueData = 255  # 0xFF

New-Item -Path $RegPath -Force | Out-Null
New-ItemProperty -Path $RegPath -Name $ValueName -PropertyType DWord -Value $ValueData -Force | Out-Null

# Verify (ensures the configured value matches the STIG requirement)
$CurrentValue = (Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction Stop).$ValueName
if ($CurrentValue -ne $ValueData) {
    throw "Verification failed: $ValueName is $CurrentValue; expected $ValueData (0x{0:X2})." -f $ValueData
}
