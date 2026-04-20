# Detection Analysis — Findings and Recommendations

## Summary

Three custom detection rules were developed, deployed, and tested against controlled attack simulations targeting PowerShell abuse, scheduled task persistence, and SMB lateral movement. This analysis covers detection efficacy, false positive observations, coverage gaps, and recommended improvements.

---

## What Worked

### PowerShell Detection (Rules 100100, 100101)
- Both `-ExecutionPolicy Bypass` and `-EncodedCommand` variants detected consistently across all test cases
- The PCRE2 regex handled command-line abbreviations (`-ep`, `-enc`) without modification
- Parent process context (captured by Sysmon Event ID 1) provided useful triage information — `cmd.exe` as a parent was a stronger indicator than `explorer.exe`
- Alert levels (12 for bypass, 14 for encoded) provided appropriate prioritization

### Scheduled Task Detection (Rules 100200–100202)
- Base rule (100200) triggered on every `schtasks /create` execution
- Child rules correctly identified SYSTEM-level execution and persistence triggers (logon/startup)
- Rule chaining worked as designed — a single command generated multiple alerts at different severity levels, giving analysts immediate context

### SMB Lateral Movement (Rules 100300–100301)
- PsExec-based lateral movement was reliably detected
- The elevated rule (100301) correctly identified `PsExec.exe` and `net.exe` as initiating processes
- Suppression rule (100302) reduced noise from `svchost.exe` and `lsass.exe` system-level SMB traffic

---

## What Didn't Trigger or Underperformed

### SMB — `net use` Without Process Match
- `net use` to mount an admin share was detected by the base rule (100300, Sysmon Event ID 3) but the initiating process was logged as `System` (PID 4) in some cases rather than `net.exe`. This caused rule 100301 to miss certain `net use` invocations.
- **Root cause:** Windows routes SMB connections through the System process after the initial `net use` command completes. Sysmon captures the network connection at the kernel level, not at the `net.exe` process level.

### Encoded Command — Partial Obfuscation
- The encoded command rule (100101) does not detect PowerShell invocations where the `-EncodedCommand` flag is passed via an intermediary script or environment variable rather than directly on the command line.
- This is a known limitation — the rule only inspects `CommandLine`, not the decoded content of the base64 payload.

### Scheduled Task — COM Object Creation
- Tasks created programmatically via the Task Scheduler COM API (rather than `schtasks.exe`) are not detected by the current rules. This is a significant gap since advanced adversaries and some malware families avoid `schtasks.exe` entirely.

---

## False Positives Observed

| Rule | False Positive Source | Frequency | Action Taken |
|---|---|---|---|
| 100200 | Windows Task Scheduler service creating maintenance tasks during updates | Low (2 occurrences during testing) | Documented; would whitelist by task name in production |
| 100300 | Domain Controller replication and GPO distribution over SMB | High (continuous) | Suppression rule (100302) reduced severity; DC-to-DC traffic should be excluded by source IP in production |
| 100100 | None observed during testing | N/A | No action required |

The SMB base rule (100300) generated the most noise. In a production environment, this rule would require significant tuning or should only be deployed with the elevated child rule (100301) as the primary detection.

---

## Detection Coverage Gaps

| Gap | MITRE Technique | Impact | Recommended Mitigation |
|---|---|---|---|
| No detection for PowerShell without bypass flags | T1059.001 | Adversaries using default policy or `Set-ExecutionPolicy` in-session are missed | Add rule for suspicious PowerShell module loads (Event ID 7) or script block logging (Windows Event ID 4104) |
| COM-based scheduled task creation | T1053.005 | Bypasses `schtasks.exe` process creation detection | Monitor Event ID 4698 (Windows Security Log) for task registration events |
| Unsigned binary execution | T1059 | No detection for execution of unsigned/untrusted binaries | Implement Sysmon Event ID 1 rules checking `Image` against known-good paths |
| Credential access | T1003 | No detection for credential dumping (LSASS access, SAM extraction) | Add Sysmon Event ID 10 (Process Access) rules for `lsass.exe` access |
| WMI lateral movement | T1047 | `wmic.exe` remote execution not covered | Add Sysmon Event ID 1 rule for `wmic.exe /node:` remote execution patterns |

---

## Recommended Improvements

### Short-Term
- **Add Windows Security Event correlation:** Supplement Sysmon rules with Windows Event ID 4624 (logon type 3) correlation for lateral movement confirmation
- **Deploy PowerShell Script Block Logging:** Enable via GPO and create Wazuh rules for Windows Event ID 4104 to capture full script content regardless of command-line obfuscation
- **Tune SMB base rule:** Exclude DC-to-DC traffic by source IP to reduce false positive volume by approximately 60–70%

### Medium-Term
- **Expand MITRE coverage:** Priority additions should target Credential Access (T1003), Defense Evasion (T1562), and Discovery (T1087) tactics
- **Implement frequency-based rules:** Wazuh supports `<frequency>` and `<timeframe>` elements — use these to detect lateral movement sweeps (multiple SMB connections across hosts in a short window)
- **Add file integrity monitoring:** Deploy Wazuh FIM (`<syscheck>`) on sensitive directories (`C:\Windows\Tasks\`, `C:\Windows\System32\Tasks\`) for persistence detection independent of process creation

### Long-Term
- **Integrate threat intelligence:** Import IOC feeds (file hashes, IP addresses) into Wazuh CDB lists for automated enrichment
- **Automate testing:** Script attack simulations for regression testing after rule changes
- **Deploy Sigma rules:** Convert community Sigma detection rules to Wazuh format for broader detection coverage without writing every rule from scratch

---

## Conclusion

The detection pipeline is operational and validated against three MITRE ATT&CK techniques. PowerShell and scheduled task detections performed reliably. SMB lateral movement detection requires additional tuning to manage false positive volume from legitimate domain traffic. The primary gaps — COM-based task creation, credential access, and WMI lateral movement — represent the next priority for rule development.
