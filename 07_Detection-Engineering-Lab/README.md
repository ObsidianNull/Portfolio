# Detection Engineering Lab — Wazuh + Sysmon in Active Directory

## Overview

Purpose-built detection engineering environment using Wazuh SIEM and Sysmon telemetry across a domain-joined Windows network. The lab implements a full logging pipeline from endpoint instrumentation through centralized analysis, with custom detection rules validated against simulated adversary techniques mapped to MITRE ATT&CK.

## Objectives

- Architect a segmented Active Directory lab environment with centralized SIEM collection
- Deploy and tune Sysmon for high-fidelity endpoint telemetry
- Engineer custom Wazuh detection rules targeting documented attack techniques
- Validate detection coverage through controlled attack simulation
- Identify gaps, false positives, and tuning requirements through structured analysis

## Environment

| System | OS | Role | IP Address |
|---|---|---|---|
| DC01 | Windows Server 2022 | Domain Controller (AD DS, DNS, GPO) | 192.168.56.10 |
| WS01 | Windows 10 Enterprise | Domain-joined endpoint | 192.168.56.20 |
| WAZUH-SVR | Ubuntu 22.04 LTS | Wazuh Manager + Dashboard | 192.168.56.40 |

**Network:** VMware Workstation host-only adapter (192.168.56.0/24), fully isolated from production.

## Architecture Summary

Sysmon is deployed to both Windows systems via Group Policy, generating telemetry for process creation, network connections, file creation, and registry events. The Wazuh agent forwards Sysmon logs to the Wazuh Manager over an encrypted channel (port 1514). Detection rules on the manager evaluate inbound events against custom XML rule definitions, triggering alerts surfaced through the Wazuh Dashboard.

See [architecture/overview.md](architecture/overview.md) for the full architecture breakdown.

## Detection Coverage

| Detection | MITRE ATT&CK | Technique ID | Data Source | Wazuh Rule |
|---|---|---|---|---|
| PowerShell Execution Policy Bypass | Execution | T1059.001 | Sysmon Event ID 1 | [powershell.xml](detections/wazuh-rules/powershell.xml) |
| Scheduled Task Persistence | Persistence | T1053.005 | Sysmon Event ID 2 | [persistence.xml](detections/wazuh-rules/persistence.xml) |
| Lateral Movement via SMB | Lateral Movement | T1021.002 | Sysmon Event ID 3 | [lateral.xml](detections/wazuh-rules/lateral.xml) |

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Detection Status |
|---|---|---|---|
| Execution | T1059.001 | PowerShell | Detected — custom rule triggers on `-ExecutionPolicy Bypass` and encoded commands |
| Persistence | T1053.005 | Scheduled Task | Detected — custom rule triggers on `schtasks.exe /create` with suspicious parameters |
| Lateral Movement | T1021.002 | SMB/Windows Admin Shares | Detected — custom rule triggers on SMB connections to `C$`/`ADMIN$` shares |

## Project Structure

```
07_Detection-Engineering-Lab/
├── README.md
├── architecture/
│   └── overview.md
├── setup/
│   ├── vmware-network.md
│   ├── active-directory.md
│   ├── wazuh-setup.md
│   └── sysmon-install.md
├── detections/
│   ├── powershell-abuse.md
│   ├── persistence-schtasks.md
│   ├── lateral-movement.md
│   └── wazuh-rules/
│       ├── powershell.xml
│       ├── persistence.xml
│       └── lateral.xml
├── attack-simulation/
│   └── test-scenarios.md
└── findings/
    └── detection-analysis.md
```

## Key Outcomes

- **End-to-end logging pipeline** operational from Sysmon instrumentation through Wazuh alert generation
- **3 custom detection rules** authored, deployed, and validated against live attack simulation
- **False positive analysis** completed with tuning recommendations documented per rule
- **Detection gaps identified** — notably, Sysmon Event ID 3 network telemetry required additional filtering to reduce noise from legitimate SMB traffic
- **MITRE ATT&CK alignment** across all detections with documented technique-to-rule mappings

## Tools Used

- VMware Workstation Pro
- Windows Server 2022 / Windows 10 Enterprise
- Ubuntu 22.04 LTS
- Wazuh 4.x (Manager, Agent, Dashboard)
- Sysmon (SwiftOnSecurity config, customized)
- PowerShell, cmd.exe, PsExec
