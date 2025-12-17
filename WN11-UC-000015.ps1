#Requires -Version 5.1
<#
.SYNOPSIS
    Remediates DISA STIG WN11-UC-000015 by disabling toast notifications on the lock screen (Current User).

.DESCRIPTION
    This script enforces the STIG requirement by setting the following registry value:

        Hive      : HKEY_CURRENT_USER (HKCU)
        Path      : SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications
        Value     : NoToastApplicationNotificationOnLockScreen
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
    STIG-ID         : WN11-UC-000015

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    Run in the security context of the user you want to configure (HKCU).
    .\WN11-UC-000015.ps1

.EXAMPLE
    .\WN11-UC-000015.ps1
#>

$RegPath   = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
$ValueName = "NoToastApplicationNotificationOnLockScreen"
$ValueData = 1

if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

New-ItemProperty -Path $RegPath -Name $ValueName -PropertyType DWord -Value $ValueData -Force | Out-Null

# Verify
(Get-ItemProperty -Path $RegPath -Name $ValueName).$ValueName
