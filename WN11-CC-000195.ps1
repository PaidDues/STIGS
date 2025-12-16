#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Remediates DISA STIG WN11-CC-000195 by enabling Enhanced anti-spoofing for Windows Hello facial recognition.

.DESCRIPTION
    Sets the following policy registry value:

        Hive      : HKEY_LOCAL_MACHINE (HKLM)
        Path      : SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures
        Value     : EnhancedAntiSpoofing
        Type      : REG_DWORD
        Required  : 1

    If the key path does not exist, it is created. The script then verifies the final value.

.NOTES
    Author          : Max Dues
    LinkedIn        : linkedin.com/in/mdues/
    GitHub          : github.com/PaidDues
    Date Created    : 2025-12-16
    Last Modified   : 2025-12-16
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000195

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    Run as administrator.

.EXAMPLE
    .\WN11-CC-000195.ps1
#>

$RegPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures'
$Name    = 'EnhancedAntiSpoofing'
$Value   = 1

New-Item -Path $RegPath -Force | Out-Null
New-ItemProperty -Path $RegPath -Name $Name -PropertyType DWord -Value $Value -Force | Out-Null

# Verify
$Actual = (Get-ItemProperty -Path $RegPath -Name $Name -ErrorAction Stop).$Name
if ($Actual -ne $Value) { throw "Verification failed: $RegPath\$Name is '$Actual' (expected '$Value')." }

Write-Output "$Name=$Actual"
