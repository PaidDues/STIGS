#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Remediates DISA STIG WN11-AC-000020 by enforcing password history of 24 unique passwords.

.DESCRIPTION
    Sets "Enforce password history" (PasswordHistorySize) to the specified value using:
      net accounts /uniquepw:<n>

    SCOPE: This script configures LOCAL security policy and is intended for 
    standalone/workgroup systems. For domain-joined systems, the STIG requires
    this setting be configured via domain Group Policy, which will override 
    this local setting.
    
.NOTES
    Author          : Max Dues
    LinkedIn        : linkedin.com/in/mdues/
    GitHub          : github.com/PaidDues
    Date Created    : 2025-12-16
    Last Modified   : 2025-12-16
    Version         : 1.0
    STIG-ID         : WN11-AC-000020

.PARAMETER HistorySize
    Number of unique passwords remembered (0-24). STIG requires 24.

.EXAMPLE
    .\WN11-AC-000020.ps1

.EXAMPLE
    .\WN11-AC-000020.ps1 -HistorySize 24
#>

[CmdletBinding()]
param(
    [ValidateRange(0,24)]
    [int]$HistorySize = 24
)

$ErrorActionPreference = 'Stop'

# Remediate
& net accounts "/uniquepw:$HistorySize" | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Remediation failed: 'net accounts' returned exit code $LASTEXITCODE."
}

# Verify (parses `net accounts` output) - UPDATED regex to match the colon format
$netOut = & net accounts 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "Verification failed: 'net accounts' returned exit code $LASTEXITCODE."
}

$match = ($netOut | Select-String -Pattern 'Length of password history maintained:\s*(\d+)\s*$').Matches
if (-not $match) {
    Write-Warning "Could not parse verification output. Raw output:"
    $netOut
    exit 1
}

$current = [int]$match[0].Groups[1].Value
if ($current -ne $HistorySize) {
    throw "Non-compliant: expected $HistorySize, found $current."
}

Write-Output "Compliant (WN11-AC-000020): Enforce password history = $current."
