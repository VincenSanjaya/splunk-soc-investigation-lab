# Remediation and Response Recommendations — Splunk SOC Investigation Lab

## Purpose and Evidence Boundary

This document provides **defensive follow-up actions** for suspicious behaviors observed in imported Windows telemetry. The investigation used **sample CSV events**, not an active corporate incident. The three findings have **not** been proven to involve the same host or attack chain. Recommendations below are conditional actions for an authorized response team, not actions performed in this lab.

## 1. Suspicious LSASS Process Access

**Observed evidence:** Sysmon Event ID 10 recorded an executable named `mimikatz.exe` accessing `C:\Windows\system32\lsass.exe` with access mask `0x00001010`.

**Risk:** Potential access to sensitive authentication material. The event does **not** establish that credentials were successfully dumped.

**Recommended response:**

1. **Validate identity and provenance:** Determine the real host, user, binary path, hash, signer, process GUID, and whether an approved security test was underway. A filename alone does not authenticate the executable.
2. **Expand telemetry:** Review Sysmon process creation/access, EDR alerts, DLL and file activity, Windows Security logs, and any relevant memory-access or dump-file evidence.
3. **Contain if corroborated:** For a genuinely compromised endpoint, follow the incident-response playbook for network isolation and evidence preservation. Avoid indiscriminate process termination or deletion before collection.
4. **Assess credential exposure:** If exposure is confirmed or strongly supported, coordinate credential resets, privileged account review, session invalidation, and lateral-movement hunting.
5. **Harden endpoints:** Evaluate Microsoft Defender protections, Credential Guard, LSA protection, least privilege, and application control where compatible with the environment.

**Validation target:** Subsequent LSASS access alerts include reliable host, process, identity, and EDR context, and any approved testing is distinguishable from unexpected access.

**Relevant ATT&CK hypothesis:** [T1003.001 — LSASS Memory](https://attack.mitre.org/techniques/T1003/001/).

## 2. IIS Worker Process Spawning Encoded PowerShell

**Observed evidence:** Sysmon Event ID 1 recorded `w3wp.exe` → `powershell.exe` under `IIS APPPOOL\DefaultAppPool` with `-nop -noni -enc` arguments.

**Risk:** Potential unauthorized command execution in a web-application context. The sample event does **not** prove exploitation or identify a final malicious payload.

**Recommended response:**

1. **Correlate with web activity:** Inspect IIS access logs, reverse-proxy/WAF logs, application logs, authentication events, and request parameters near the process timestamp.
2. **Inspect process ancestry:** Obtain process GUID/PID, full command line, executed script, child processes, network connections, and file changes from endpoint tooling.
3. **Review application security:** Identify vulnerable upload handlers, command execution paths, unsafe deserialization, misconfigurations, or other plausible entry points **only if supported by evidence**.
4. **Apply least privilege:** Limit the application pool identity's permissions and restrict unnecessary access to scripting tools, filesystem paths, and sensitive resources.
5. **Harden execution:** Evaluate constrained PowerShell policies, application control (WDAC/AppLocker where appropriate), EDR blocking, and web application security controls. Test compatibility before enforcement.
6. **Patch and retest:** If a vulnerable application or component is verified, remediate the root cause and check that the suspicious execution path is closed.

**Validation target:** A monitored test environment flags unexpected IIS-to-PowerShell launches, and legitimate maintenance workflows are documented and tuned to reduce false positives.

**Relevant ATT&CK:** [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/); [T1027 — Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/) as a candidate for encoded/obfuscated execution.

## 3. PowerShell Credential Prompt and Password Handling

**Observed evidence:** PowerShell Event ID 4104 included `Invoke-LoginPrompt`, `PromptForCredential`, `GetNetworkCredential().Password`, and `ValidateCredentials`, followed by output that included a `Password` property.

**Risk:** Potential credential harvesting or inadvertent credential disclosure. The script content alone does **not** prove that a person entered credentials or that they were transmitted anywhere.

**Recommended response:**

1. **Determine origin:** Locate the host, user, script path, execution session, parent process, and initiating action from complete event records and endpoint telemetry.
2. **Review authorization:** Determine whether the script is approved administrative automation or an unexpected prompt impersonating a trusted login dialog.
3. **Check exposure channels:** Inspect script output, transcripts, logs, files, clipboard-related artifacts, network traffic, and downstream processes for any disclosure of passwords.
4. **Protect accounts when warranted:** If exposure is verified or reasonably suspected, revoke active sessions, reset affected credentials, investigate suspicious logins, and ensure MFA is enabled.
5. **Improve secret handling:** Avoid printing plaintext passwords, minimize credentials held in memory, use approved secret-management workflows, and limit interactive prompts in automation.
6. **Increase user awareness:** Train users to verify unexpected credential dialogs and report suspicious prompts through the official security process.

**Validation target:** Suspicious password-handling scripts are detected with process and user context; authorized tools no longer output plaintext credential material.

**Relevant ATT&CK:** [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/). More specific credential-theft classification requires corroboration.

## 4. Base64 / GZip PowerShell Script Block

**Observed evidence:** Another Event ID 4104 included `FromBase64String`, `GZipStream`, and `CompressionMode::Decompress`.

**Response approach:** Preserve the complete script block and its metadata; decode/decompress recovered data **offline and statically**, without executing it; inspect resulting content and hashes using approved analysis tools; then correlate against process, filesystem, and network telemetry. Compression by itself is **not malicious**, so avoid alerting solely on these keywords.

**Relevant ATT&CK candidates:** [T1027](https://attack.mitre.org/techniques/T1027/), [T1140](https://attack.mitre.org/techniques/T1140/) when the context supports them.

## 5. SIEM Detection Engineering Improvements

The lab matched **four events** with simple SPL patterns. Before deploying alerts in production:

- **Enrich** searches with asset criticality, user identity, hashes, signer data, host, process GUID, parent/child lineage, and EDR verdicts.
- **Correlate** Windows Security logs, Sysmon events, PowerShell 4104, IIS logs, and network events using reliable identifiers and normalized timestamps.
- **Tune** benign administration workflows and allowlists carefully; document exceptions and review them periodically.
- **Test** detections using approved, controlled simulations; assess precision, coverage, false positives, and analyst workload.
- **Operationalize** with clear severity, investigation steps, escalation paths, and evidence-retention requirements.
- **Verify ingestion hygiene** by checking event/metrics index types, field parsing, timestamp timezone, and retention periods.

See [`detections/soc-detection-queries.spl`](detections/soc-detection-queries.spl) for the lab searches. They are **triage searches**, not a tested production detection package.

## 6. Priority and Verification Matrix

| Finding | Triage priority | First validation question | Evidence needed to confirm impact |
|---|---|---|---|
| Mimikatz-named process → LSASS | High | Is this an authorized tool/test on a known endpoint? | Host/EDR evidence of credential material access or dump artifacts |
| IIS `w3wp.exe` → encoded PowerShell | High | What web request or application action spawned PowerShell? | IIS logs, process GUIDs, decoded script, network/file artifacts |
| PowerShell credential prompt | High | Was this script authorized and actually presented to a user? | Execution context, user interaction, captured/output artifacts |
| Base64/GZip script block | Investigate in context | What is the decoded content? | Complete script and corroborating execution artifacts |

**Important:** Priority is a **triage recommendation**, not a declaration of confirmed compromise.

## 7. Conclusion

The lab identified meaningful investigation leads and demonstrates how to translate suspicious Windows telemetry into **proportionate defensive follow-up**. In a real incident, actions must be evidence-led and authorized, with containment, evidence preservation, credential protection, and root-cause remediation adapted to the affected environment.

For what was actually observed, see the [SOC Investigation Report](reports/SOC-Investigation-Report.md) and [Methodology](methodology.md).
