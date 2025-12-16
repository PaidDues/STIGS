<#
.SYNOPSIS
    This PowerShell script ensures that the maximum size of the Windows Application event log is at least 32768 KB (32 MB).

.NOTES
    Author          : Max Dues
    LinkedIn        : linkedin.com/in/mdues/
    GitHub          : github.com/PaidDues
    Date Created    : 2025-12-16
    Last Modified   : 2025-12-16
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AU-000500

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Run as administrator.
    Example:
    PS C:\> .\STIG-ID-WN11-AU-000500.ps1 
#>

#Requires -RunAsAdministrator

$Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"

# Ensure the policy key exists
New-Item -Path $Path -Force | Out-Null

# Set Application event log max size (KB) to 32768 (0x8000) or greater
New-ItemProperty -Path $Path -Name "MaxSize" -PropertyType DWord -Value 32768 -Force | Out-Null

# Verify
Get-ItemProperty -Path $Path -Name "MaxSize" | Select-Object PSPath, MaxSize

