# Sysmon Installation and Configuration

## Sysmon Version

Sysmon v15.x deployed across all Windows systems. Downloaded from [Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).

## Configuration

Base configuration derived from [SwiftOnSecurity's sysmonconfig-export.xml](https://github.com/SwiftOnSecurity/sysmon-config), with the following modifications:

- **Event ID 3 (Network Connection):** Enabled logging for inbound SMB connections (port 445) — disabled by default in SwiftOnSecurity config. Required for lateral movement detection.
- **Event ID 1 (Process Creation):** Added explicit include rules for `schtasks.exe` and `powershell.exe` with command-line logging.
- **Event ID 11 (File Create):** Included monitoring for files written to `C:\Windows\Tasks\` and `C:\Windows\System32\Tasks\`.

## Installation

Sysmon installed via command line with the custom configuration:

```cmd
sysmon64.exe -accepteula -i sysmonconfig-lab.xml
```

To update configuration without reinstalling:

```cmd
sysmon64.exe -c sysmonconfig-lab.xml
```

## GPO Deployment

For automated deployment across domain-joined systems:

1. Sysmon binary and config file placed on `\\DC01\NETLOGON\Sysmon\`
2. Startup script created to check for existing installation and install/update:

```batch
@echo off
sc query Sysmon64 >nul 2>&1
if %errorlevel% neq 0 (
    "\\DC01\NETLOGON\Sysmon\sysmon64.exe" -accepteula -i "\\DC01\NETLOGON\Sysmon\sysmonconfig-lab.xml"
) else (
    "\\DC01\NETLOGON\Sysmon\sysmon64.exe" -c "\\DC01\NETLOGON\Sysmon\sysmonconfig-lab.xml"
)
```

3. Script linked to `Deploy-Sysmon` GPO under Computer Configuration → Windows Settings → Scripts → Startup

## Validation

Confirm Sysmon is running and generating events:

```powershell
# Service status
Get-Service Sysmon64

# Check for recent events
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 | Format-List
```

## Key Event IDs Used in This Lab

| Event ID | Description | Detection Use |
|---|---|---|
| 1 | Process Creation | PowerShell execution, schtasks execution |
| 3 | Network Connection | SMB lateral movement |
| 11 | File Create | Scheduled task file drops |
| 13 | Registry Value Set | Persistence mechanisms (supplementary) |

Event ID 1 is the highest-value source for this lab. Command-line arguments captured in Sysmon Event ID 1 are the primary indicator for both PowerShell abuse and scheduled task creation detections.
