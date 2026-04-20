# Detection: Scheduled Task Persistence via schtasks.exe

## Threat Description

Adversaries use `schtasks.exe` to create scheduled tasks that execute malicious payloads at system startup, user logon, or on a recurring schedule. This is one of the most common persistence mechanisms in real-world intrusions because it survives reboots, blends in with legitimate scheduled tasks, and can run under SYSTEM context.

APT groups and commodity malware routinely create scheduled tasks as a persistence fallback. The technique is effective because Windows environments typically have dozens of legitimate scheduled tasks, making manual review impractical without automated detection.

## MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| **Tactic** | Persistence |
| **Technique** | T1053.005 — Scheduled Task/Job: Scheduled Task |
| **Sub-technique** | T1053.005 |

## Data Source

- **Sysmon Event ID 1** — Process Creation
- **Key Fields:** `Image`, `CommandLine`, `ParentImage`, `User`
- **Supplementary:** Sysmon Event ID 11 (File Create) for task XML files written to `C:\Windows\System32\Tasks\`

## Detection Logic

The rule triggers when `schtasks.exe` is executed with the `/create` flag. Additional analysis is performed on the command-line arguments to identify suspicious indicators:

- Task configured to run at logon (`/sc onlogon`) or startup (`/sc onstart`)
- Task configured to run as SYSTEM (`/ru SYSTEM`)
- Task executing binaries from unusual paths (e.g., `C:\Temp\`, `C:\Users\Public\`, `%APPDATA%`)

The rule is structured as a base detection (any `schtasks /create`) with a higher-severity child rule for tasks that combine suspicious scheduling with SYSTEM-level execution.

## Wazuh Rule

See [wazuh-rules/persistence.xml](wazuh-rules/persistence.xml)

```xml
<group name="sysmon,persistence,T1053.005,">
  <rule id="100200" level="10">
    <if_sid>61603</if_sid>
    <field name="win.eventdata.image" type="pcre2">(?i)schtasks\.exe$</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)/create\s</field>
    <description>Scheduled task created via schtasks.exe — T1053.005</description>
    <mitre>
      <id>T1053.005</id>
    </mitre>
    <options>no_full_log</options>
  </rule>

  <rule id="100201" level="14">
    <if_sid>100200</if_sid>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)/ru\s+(system|SYSTEM)</field>
    <description>Scheduled task created with SYSTEM privileges — T1053.005</description>
    <mitre>
      <id>T1053.005</id>
    </mitre>
    <options>no_full_log</options>
  </rule>

  <rule id="100202" level="14">
    <if_sid>100200</if_sid>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)/sc\s+(onlogon|onstart|onidle)</field>
    <description>Scheduled task with persistence trigger (logon/startup) — T1053.005</description>
    <mitre>
      <id>T1053.005</id>
    </mitre>
    <options>no_full_log</options>
  </rule>
</group>
```

## Attack Command Used

```cmd
# Basic persistence — runs calc.exe at logon as SYSTEM
schtasks /create /tn "WindowsUpdate" /tr "C:\Temp\beacon.exe" /sc onlogon /ru SYSTEM /f

# Recurring task — executes every 15 minutes
schtasks /create /tn "HealthCheck" /tr "powershell.exe -ep bypass -File C:\Users\Public\update.ps1" /sc minute /mo 15 /ru SYSTEM /f

# One-time execution at startup
schtasks /create /tn "Maintenance" /tr "C:\ProgramData\svchost.exe" /sc onstart /ru SYSTEM /f
```

## Observed Behavior in Logs

Sysmon Event ID 2 captured:

```
EventID: 1
Image: C:\Windows\System32\schtasks.exe
CommandLine: schtasks /create /tn "WindowsUpdate" /tr "C:\Temp\beacon.exe" /sc onlogon /ru SYSTEM /f
ParentImage: C:\Windows\System32\cmd.exe
User: LAB\svc-admin
IntegrityLevel: High
```

Wazuh alerts generated:
- **Rule 100200** (level 10): Scheduled task created via schtasks.exe
- **Rule 100201** (level 14): Scheduled task created with SYSTEM privileges
- **Rule 100202** (level 14): Scheduled task with persistence trigger (logon/startup)

Both child rules (100201, 100202) fired because the command contained both `/ru SYSTEM` and `/sc onlogon`.

## False Positives and Tuning

**Known false positives:**
- Software update mechanisms (e.g., Google Update, Adobe Updater) that create scheduled tasks during installation
- IT administration scripts that deploy scheduled tasks for maintenance automation
- Windows Defender definition update tasks

**Tuning recommendations:**
- Whitelist known task names created by trusted software using a child rule with level 0
- Focus high-severity alerting on tasks that execute from non-standard paths (`C:\Temp`, `C:\Users\Public`, `%APPDATA%`)
- Cross-reference with Sysmon Event ID 11 to detect task XML file creation in `C:\Windows\System32\Tasks\` for additional confidence
- Consider aggregating: a single `schtasks /create` is worth investigating, but repeated creation attempts in a short window is a stronger indicator
