<#
.SYNOPSIS
    Implements DISA STIG WN11-SO-000070 by setting the machine inactivity limit (InactivityTimeoutSecs).

.DESCRIPTION
    Configures the following registry value to enforce the machine inactivity limit:
      HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\InactivityTimeoutSecs (REG_DWORD)
    A value of 1..900 seconds is compliant; 0 disables the control.

.EXAMPLE
    .\WN11-SO-000070.ps1

.EXAMPLE
    .\WN11-SO-000070.ps1 -TimeoutSeconds 900

.NOTES
    Author          : Max Dues
    LinkedIn        : linkedin.com/in/mdues/
    GitHub          : github.com/PaidDues
    Date Created    : 2025-12-16
    Last Modified   : 2025-12-16
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-SO-000070

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. :
#>

#Requires -RunAsAdministrator
param([ValidateRange(1,900)][int]$TimeoutSeconds=900)

$path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$name='InactivityTimeoutSecs'

if(-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
New-ItemProperty -Path $path -Name $name -PropertyType DWord -Value $TimeoutSeconds -Force | Out-Null

(Get-ItemProperty -Path $path -Name $name).$name
