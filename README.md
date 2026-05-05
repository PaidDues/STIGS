# 🔒 Windows 11 DISA STIG Remediations

A collection of PowerShell scripts that automate the remediation and verification of DISA Security Technical Implementation Guide (STIG) findings for **Windows 11** endpoints.

Each script targets a specific STIG rule, applies the required configuration change, and verifies the result, turning hours of manual hardening into a single command.

---

## The Problem I'm Solving

Manual STIG remediation doesn't scale. Each finding requires navigating registry paths, applying precise values, and verifying the result. That process is time-intensive, difficult to reproduce consistently, and easy to get wrong when done by hand across a fleet of endpoints.

These scripts eliminate that risk. Each one isolates a single STIG finding, applies the required configuration, and validates the outcome, producing a clear, auditable result every time. They're written to be straightforward to review, easy to integrate into existing hardening workflows, and ready to hand off to the next analyst on the team.

This repo is a living portfolio piece. More scripts are on the way as I continue working through the Windows 11 STIG benchmark.

---

## Scripts

| Script | STIG ID | Category | What It Does |
|--------|---------|----------|--------------|
| `WN11-AC-000010.ps1` | WN11-AC-000010 | Account Policy | Sets the account lockout threshold to 3 or fewer invalid attempts |
| `WN11-AC-000020.ps1` | WN11-AC-000020 | Account Policy | Enforces password history of 24 unique passwords remembered |
| `WN11-AU-000500.ps1` | WN11-AU-000500 | Event Log | Sets the Application event log maximum size to 32768 KB |
| `WN11-AU-000505.ps1` | WN11-AU-000505 | Event Log | Sets the Security event log maximum size to 1024000 KB |
| `WN11-CC-000005.ps1` | WN11-CC-000005 | System Config | Disables camera access from the lock screen |
| `WN11-CC-000100.ps1` | WN11-CC-000100 | System Config | Prevents downloading print driver packages over HTTP |
| `WN11-CC-000190.ps1` | WN11-CC-000190 | System Config | Disables AutoPlay for all drives |
| `WN11-CC-000195.ps1` | WN11-CC-000195 | System Config | Enables enhanced anti-spoofing for Windows Hello facial recognition |
| `WN11-SO-000070.ps1` | WN11-SO-000070 | Security Options | Sets the machine inactivity timeout to 900 seconds (15 min) or less |
| `WN11-UC-000015.ps1` | WN11-UC-000015 | User Config | Disables toast notifications on the lock screen (per-user, HKCU) |

> **Category Key:** AC = Account Policy · AU = Event Log Sizing · CC = Configuration Control · SO = Security Options · UC = User Configuration

---

## Usage

All scripts require **Administrator** privileges (except `WN11-UC-000015.ps1`, which writes to `HKCU` and runs in the current user's context).

```powershell
# Run a single remediation with default settings
.\WN11-AC-000010.ps1

# Pass a custom parameter (where supported)
.\WN11-AC-000010.ps1 -LockoutThreshold 2
.\WN11-AU-000505.ps1 -MaxSizeKB 2048000
.\WN11-SO-000070.ps1 -TimeoutSeconds 600
```

To run all remediations at once:

```powershell
Get-ChildItem -Path .\*.ps1 | ForEach-Object { & $_.FullName }
```

Each script outputs a clear success/failure message and returns an appropriate exit code (`0` for success, `1` for failure).

---

## Script Structure

Every script follows the same pattern for consistency and auditability:

```
#Requires -RunAsAdministrator

1. Comment-based help (.SYNOPSIS, .DESCRIPTION, .NOTES, .EXAMPLE)
2. Parameter declaration with validation
3. Ensure registry path / policy key exists
4. Apply the remediation
5. Verify the change
6. Output result with before/after or compliant/non-compliant status
```

---

## Requirements

- **OS:** Windows 11
- **Shell:** PowerShell 5.1+
- **Privileges:** Must run as Administrator (see note on `WN11-UC-000015.ps1` above)
- **Note:** On domain-joined systems, Group Policy may override local settings applied by these scripts. Verify with your domain admin.

---

## Verification

After running a script, you can confirm the change was applied:

```powershell
# Example: verify account lockout threshold
net accounts

# Example: verify a registry-based control
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenCamera"
```

Each script also performs its own post-remediation verification and will warn you if the expected value wasn't applied (e.g., due to a domain GPO override).

---

## Disclaimer

These scripts are provided as a portfolio demonstration of STIG remediation automation. They are **not** a substitute for a full STIG compliance program. Always validate against the latest DISA STIG benchmarks and test in a non-production environment before deploying.

---

## Author

**Max Dues**
- [LinkedIn](https://linkedin.com/in/mdues/)
- [GitHub](https://github.com/PaidDues)

---

## License

This project is open source. See individual script headers for version and authorship details.
