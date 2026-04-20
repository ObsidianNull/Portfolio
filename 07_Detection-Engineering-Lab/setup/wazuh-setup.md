# Wazuh Setup

## Installation Method

Wazuh installed on Ubuntu 22.04 LTS using the all-in-one deployment (Manager, Indexer, Dashboard on a single node). This is appropriate for lab environments; production deployments should separate components.

Installation was performed using the Wazuh installation assistant:

```bash
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash wazuh-install.sh -a
```

The `-a` flag performs an all-in-one deployment. Default admin credentials are generated and displayed at the end of installation — these were changed immediately.

## Post-Install Configuration

### Manager — `/var/ossec/etc/ossec.conf`

Key configuration changes:

```xml
<ossec_config>
  <global>
    <logall>yes</logall>
    <logall_json>yes</logall_json>
  </global>

  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
  </remote>
</ossec_config>
```

- `logall` and `logall_json` enabled to ensure all events (not just alerts) are indexed — critical for detection development and tuning
- Agent communication set to TCP for reliability over UDP

### Custom Rules Directory

Custom detection rules are placed in `/var/ossec/etc/rules/` with filenames prefixed `local_` to avoid conflicts with upstream rule updates:

```
/var/ossec/etc/rules/
├── local_powershell.xml
├── local_persistence.xml
└── local_lateral.xml
```

After adding or modifying rules:

```bash
# Validate rule syntax
sudo /var/ossec/bin/wazuh-logtest

# Restart manager to load rules
sudo systemctl restart wazuh-manager
```

## Agent Enrollment

Agents are enrolled using the manager's enrollment key. On each Windows endpoint:

```powershell
# Download agent MSI
# Install with manager IP specified
& "wazuh-agent-4.7.x.msi" /q WAZUH_MANAGER="192.168.56.100"

# Start agent service
NET START WazuhSvc
```

Agent registration is verified on the manager:

```bash
sudo /var/ossec/bin/agent_control -l
```

Both DC01 and WS01 should appear as `Active`.

## Sysmon Log Collection

The Wazuh agent must be configured to read Sysmon's event log channel. On each Windows agent, add to the agent's `ossec.conf`:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

This tells the agent to monitor the Sysmon operational log and forward events to the manager.

## Dashboard Access

Wazuh Dashboard is accessible at `https://192.168.56.100` (port 443). Default self-signed certificate — browser security exception required.

After login, verify:
- Both agents (DC01, WS01) show as **Active** under Agents
- Sysmon events are visible under **Events** with `decoder.name: windows_eventchannel`
- Rule groups include `sysmon` for Sysmon-decoded events
