#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Remediates DISA STIG WN11-CC-000100 by preventing downloading print driver packages over HTTP.

.DESCRIPTION
    Enforces the STIG requirement by configuring the following registry value:

        Hive      : HKEY_LOCAL_MACHINE (HKLM)
        Path      : SOFTWARE\Policies\Microsoft\Windows NT\Printers
        Value     : DisableWebPnPDownload
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
    STIG-ID         : WN11-CC-000100

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    Run as administrator.

.EXAMPLE
    .\WN11-CC-000100.ps1
#>

$regPath   = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
$valueName = "DisableWebPnPDownload"
$valueData = 1

# Ensure key exists
if (-not (Test-Path -Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set required value
New-ItemProperty -Path $regPath -Name $valueName -PropertyType DWord -Value $valueData -Force | Out-Null

# Verify
$actual = (Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction Stop).$valueName
if ($actual -ne $valueData) {
    throw "WN11-CC-000100 remediation failed: $valueName is $actual (expected $valueData)."
}

Write-Output "WN11-CC-000100 remediation applied successfully."
