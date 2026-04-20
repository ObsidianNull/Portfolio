# Architecture Overview

## Network Design

The lab operates on a VMware Workstation host-only network (192.168.56.0/24), providing full Layer 2/Layer 3 connectivity between all systems without any route to external networks. This isolates attack simulation traffic from production environments and prevents accidental outbound connections during testing.

VMware's host-only adapter acts as the default gateway. DNS resolution is handled by the Domain Controller (DC01) for all domain-joined systems. The Wazuh server uses static DNS configuration pointing to DC01 for name resolution and local `/etc/hosts` entries as a fallback.

## System Roles

### DC01 — Domain Controller (192.168.56.10)

- Windows Server 2022 running Active Directory Domain Services
- Provides DNS, Group Policy, and authentication services for the domain (`lab.local`)
- Distributes Sysmon installation and configuration via GPO
- Runs Wazuh agent for self-monitoring
- Hosts shared folders used in lateral movement simulation

### WS01 — Workstation (192.168.56.20)

- Windows 10 Enterprise, domain-joined to `lab.local`
- Primary attack simulation endpoint
- Runs Sysmon with SwiftOnSecurity-based configuration
- Wazuh agent installed and reporting to WAZUH-SVR
- Standard domain user and local admin accounts configured for testing different privilege levels

### WAZUH-SVR — Wazuh Manager (192.168.56.40)

- Ubuntu 22.04 LTS running Wazuh Manager, Wazuh Indexer, and Wazuh Dashboard
- Receives agent telemetry on port 1514 (encrypted)
- Dashboard accessible on port 443
- Custom detection rules deployed under `/var/ossec/etc/rules/`
- Log storage and indexing handled by Wazuh Indexer (OpenSearch-based)

## Data Flow

```
┌──────────────┐    Sysmon Events     ┌──────────────┐   Encrypted (1514/TCP)   ┌────────────────┐
│   Endpoint   │ ──────────────────── │  Wazuh Agent │ ────────────────────────  │  Wazuh Manager │
│  (WS01/DC01) │  Windows Event Log   │  (on host)   │    Agent enrollment      │  (WAZUH-SVR)   │
└──────────────┘                      └──────────────┘                          └───────┬────────┘
                                                                                        │
                                                                              Rule evaluation
                                                                              Decoding & analysis
                                                                                        │
                                                                                        ▼
                                                                              ┌────────────────┐
                                                                              │  Wazuh Indexer  │
                                                                              │  (OpenSearch)   │
                                                                              └───────┬────────┘
                                                                                      │
                                                                                      ▼
                                                                              ┌────────────────┐
                                                                              │ Wazuh Dashboard │
                                                                              │   (port 443)    │
                                                                              └────────────────┘
```

1. **Sysmon** generates telemetry (process creation, network connections, file operations) and writes to the Windows Event Log under `Microsoft-Windows-Sysmon/Operational`.
2. **Wazuh Agent** monitors the Sysmon event log channel and forwards events to the Wazuh Manager.
3. **Wazuh Manager** decodes incoming events using the Sysmon decoder, evaluates them against built-in and custom rule definitions, and generates alerts for matches.
4. **Wazuh Indexer** stores alerts and raw events for search, correlation, and historical analysis.
5. **Wazuh Dashboard** provides the analyst interface for alert triage, rule management, and visualization.

## Security Considerations

- **Network isolation:** Host-only networking ensures no lab traffic reaches external networks. No NAT or bridged adapters are configured.
- **Credential segmentation:** Lab domain credentials are unique to this environment and not reused from any other system.
- **Agent authentication:** Wazuh agents authenticate to the manager using enrollment keys. Unauthorized agents cannot register without the manager's enrollment token.
- **Snapshot discipline:** VM snapshots are taken before each attack simulation to enable clean rollback. Snapshots are labeled with date and test scenario.
- **Firewall rules:** Windows Firewall on DC01 and WS01 allows only required ports (53, 88, 135, 389, 445, 1514) within the lab subnet. All other inbound traffic is dropped.
