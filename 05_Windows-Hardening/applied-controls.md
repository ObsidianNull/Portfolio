# Applied Security Controls

## Overview
This document outlines the security controls applied to harden Windows systems based on CIS benchmarks and security best practices.

## User Account Controls

### Password Policy
- [x] Minimum password length: 14 characters
- [x] Password complexity requirements enabled
- [x] Password history: 24 passwords remembered
- [x] Maximum password age: 90 days
- [x] Account lockout threshold: 5 invalid attempts

### Account Management
- [x] Disabled Guest account
- [x] Renamed Administrator account
- [x] Limited local administrator accounts
- [x] Implemented least privilege principle

## Network Security

### Firewall Configuration
- [x] Windows Firewall enabled for all profiles
- [x] Blocked inbound connections by default
- [x] Restricted remote desktop access
- [x] Disabled unnecessary network services

### Network Services
- [x] Disabled SMBv1 protocol
- [x] Enabled SMB signing
- [x] Disabled NetBIOS over TCP/IP
- [x] Configured secure DNS settings

## System Services

### Disabled Services
- [x] Print Spooler (if not needed)
- [x] Remote Registry
- [x] Server service (workstation)
- [x] Telnet
- [x] SNMP service

### Hardened Services
- [x] Windows Update configured for automatic updates
- [x] Windows Defender real-time protection enabled
- [x] BitLocker encryption enabled

## Registry Hardening

### Security Settings
- [x] UAC enabled at highest level
- [x] Disabled autorun for all drives
- [x] Enhanced phishing protection
- [x] Credential Guard enabled (if supported)

### Audit Policy
- [x] Account logon events logged
- [x] Account management events logged
- [x] Policy change events logged
- [x] Privilege use logged

## Application Security

### Browser Hardening
- [x] SmartScreen filter enabled
- [x] Pop-up blocker enabled
- [x] Download scanning enabled
- [x] Restricted ActiveX controls

### Office Security
- [x] Macros disabled by default
- [x] Protected view enabled
- [x] Blocked dangerous file types

## Monitoring and Logging

### Event Logging
- [x] Increased security log size to 1GB
- [x] Enabled advanced audit policies
- [x] PowerShell script block logging enabled
- [x] Command line logging enabled

### Monitoring Tools
- [x] Windows Defender ATP configured
- [x] Sysmon installed and configured
- [x] Event forwarding to SIEM

## Validation

### Before Hardening
- Total vulnerabilities: [Count]
- Critical: [Count]
- High: [Count]

### After Hardening
- Total vulnerabilities: [Count]
- Critical: [Count]
- High: [Count]

### Improvement Metrics
- Vulnerability reduction: [Percentage]%
- Critical vulnerabilities eliminated: [Percentage]%
- Security score improvement: [Score]

## References
- CIS Microsoft Windows 10 Benchmark
- DISA STIGs
- Microsoft Security Baseline
- NIST Cybersecurity Framework
