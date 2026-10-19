# Methodology — Splunk SOC Investigation Lab

## 1. Objective and Scope

This lab demonstrates an evidence-based SOC triage workflow in **Splunk Cloud**: importing Windows telemetry, validating ingestion, investigating suspicious endpoint behavior using SPL, documenting findings, and identifying gaps in attribution and impact assessment.

**Scope:** Three previously prepared CSV datasets containing **43 sample events**. The datasets were not established as coming from one host, session, or incident. The project is an **offline investigation of imported samples**, not a live compromise assessment.

## 2. Environment and Data Sources

| Component | Configuration |
|---|---|
| SIEM | Splunk Cloud / Search & Reporting |
| Destination | `soc_lab1` — **Events** index |
| Source type | `csv` |
| Search time range | `All time` |
| Analysis language | Splunk Processing Language (SPL) |

| Input file | Event ID | Events | Relevant telemetry |
|---|---:|---:|---|
| `process-creation.csv` | Sysmon 1 | 40 | Process image, command line, parent process, user |
| `lsass-process-access.csv` | Sysmon 10 | 1 | Source image, target image, access mask |
| `powershell-4104.csv` | PowerShell 4104 | 2 | Captured script block content |
| **Total** | | **43** | |

The data was prepared as CSV before this Splunk investigation. **Splunk did not generate the original Windows events**, and the lab did not run the suspicious binaries or scripts.

## 3. Data Onboarding

1. Created a dedicated **Events** index named `soc_lab1`. An earlier index named `soc_lab` was a **Metrics** index and was not used for event ingestion.
2. Opened **Settings → Add Data → Upload** and imported each CSV separately.
3. Selected `csv` as the source type and `soc_lab1` as the destination index.
4. Checked the CSV preview and confirmed that key columns were searchable after upload.
5. Searched with **All time** to include historical sample timestamps.

**Timestamp caution:** Splunk displayed parsed `_time` values, but the original event timezone was not independently verified. Before correlating against other sources, validate the source format and timezone.

## 4. Ingestion Validation

```spl
index=soc_lab1
| stats count by source, EventID
```

Expected and observed total: **40 + 1 + 2 = 43 events**. This confirms the imported record counts, not completeness of activity on any endpoint.

![Ingestion validation](screenshots/02-ingestion-validation.png)

## 5. Triage and Investigation Searches

### 5.1 Review Sysmon process creation

```spl
index=soc_lab1 EventID=1
| table _time Computer User Image CommandLine ParentImage
| sort 0 _time
```

Reviewed **40 Event ID 1 records**, including IIS-related `appcmd.exe` activity and one PowerShell process creation event. Checked parent process, user context, and command-line switches rather than classifying processes from their names alone.

### 5.2 Investigate IIS-spawned encoded PowerShell

```spl
index=soc_lab1 EventID=1 Image="*powershell.exe"
| table _time User ParentImage Image ParentCommandLine CommandLine
```

Observed `w3wp.exe` launching `powershell.exe` as `IIS APPPOOL\DefaultAppPool` with `-nop -noni -enc` in the command line. The encoded command was examined **statically**; no recovered code was executed. Web exploitation, final payload behavior, and impact remain unconfirmed without IIS, host, and network evidence.

### 5.3 Investigate LSASS process access

```spl
index=soc_lab1 EventID=10
| table _time SourceImage TargetImage GrantedAccess
```

Observed a `mimikatz.exe`-named executable accessing `lsass.exe`, with `GrantedAccess=0x00001010`. Treated this as a **credential-access investigation lead**, not proof of successful dumping.

### 5.4 Review PowerShell Script Block Logging

```spl
index=soc_lab1 EventID=4104
| table _time ScriptBlockText
| sort 0 _time
```

Two 4104 records contained (a) Base64/GZip decoding logic and (b) `Invoke-LoginPrompt` with `PromptForCredential`, `GetNetworkCredential().Password`, and `ValidateCredentials`. The imported 4104 records did not expose usable host/user/script-block identifiers in the displayed results, so these were **not automatically correlated** to the IIS or LSASS findings.

## 6. Timeline Reconstruction

```spl
index=soc_lab1
| eval Activity=case(
    EventID=1, "Process Creation",
    EventID=10, "Process Access",
    EventID=4104, "PowerShell Script Block",
    true(), "Other"
)
| table _time EventID Activity Computer User Image ParentImage SourceImage TargetImage CommandLine
| sort 0 _time
```

Ordered all **43 events** by Splunk-parsed time. The ordering establishes **chronology only**. Temporal proximity alone does not demonstrate a shared source or causal attack chain.

![Timeline](screenshots/08-soc-investigation-timeline.png)

## 7. Detection Summary

A simple SPL `case()` classification identified **four matching events** across four categories:

| Category | Matches |
|---|---:|
| LSASS Process Access | 1 |
| Encoded PowerShell Execution | 1 |
| PowerShell Credential Prompt | 1 |
| PowerShell Base64 Decoding | 1 |

See [`detections/soc-detection-queries.spl`](detections/soc-detection-queries.spl) for the individual triage searches and [`screenshots/09-detection-summary.png`](screenshots/09-detection-summary.png) for evidence. These searches are **not production-ready correlation rules**. They require field normalization, host context, known-good exclusions, testing, and tuning.

## 8. Evidence Handling and Reporting

- Saved nine screenshots covering ingestion, searches, process ancestry, script blocks, timeline, and detection summary.
- Recorded observed fields and distinguished observations from hypotheses.
- Mapped techniques to MITRE ATT&CK only where the telemetry supports them.
- Wrote separate findings instead of presenting unrelated samples as a confirmed intrusion sequence.
- Did not execute malicious scripts, run Mimikatz, perform live containment, or claim confirmed credential theft.

See the [full investigation report](reports/SOC-Investigation-Report.md) and [remediation guidance](remediation.md).

## 9. Key Limitations

- Small and selectively prepared sample dataset; missing surrounding endpoint and network telemetry.
- Unverified original timezone and missing/incomplete host/session identifiers for some records.
- Sysmon Event ID 10 shows process access, not necessarily successful memory dumping.
- Event ID 4104 shows captured script content, not whether a user supplied credentials or information was exfiltrated.
- Simple string matching may produce false positives and false negatives.

**Outcome:** Successfully demonstrated a structured, repeatable **SOC triage and reporting workflow** using 43 imported Windows telemetry events.
