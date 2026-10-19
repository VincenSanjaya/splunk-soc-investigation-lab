# Splunk SOC Investigation Lab

**Windows Endpoint Threat Hunting | Splunk Cloud | Sysmon | PowerShell | SPL | MITRE ATT&CK**

An evidence-driven SOC investigation lab using **Splunk Cloud** to ingest, search, and analyze imported Windows endpoint telemetry. The project demonstrates log onboarding, detection-focused searches, process lineage analysis, PowerShell triage, timeline reconstruction, and investigation reporting.

> **Lab scope:** These are imported sample datasets, not a live corporate incident. The records have **not** been established as originating from a single host, session, or attack. Findings are documented separately; observed behaviors are distinguished from unconfirmed impact.

## Overview

| Metric | Result |
|---|---|
| SIEM platform | Splunk Cloud |
| Lab index | `soc_lab1` (Events) |
| Imported events | **43** |
| Source datasets | **3 CSV files** |
| Detection categories matched | **4** (one event each) |
| Investigation findings | **3** |
| Evidence screenshots | **9** |

### Ingested data

| Dataset | Event ID | Count |
|---|---:|---:|
| `process-creation.csv` | Sysmon 1 — Process Creation | 40 |
| `lsass-process-access.csv` | Sysmon 10 — Process Access | 1 |
| `powershell-4104.csv` | PowerShell 4104 — Script Block Logging | 2 |
| **Total** | | **43** |

## Key investigation findings

### 1. Suspicious LSASS access

A Sysmon Process Access event showed an executable named `mimikatz.exe` accessing `lsass.exe` with access mask `0x00001010`.

- **Triage significance:** Potential credential-access activity.
- **MITRE ATT&CK hypothesis:** [T1003.001 — LSASS Memory](https://attack.mitre.org/techniques/T1003/001/).
- **Evidence limitation:** Process access alone does **not** prove that credentials were dumped or stolen.

![LSASS access evidence](screenshots/01-lsass-process-access.png)

### 2. IIS worker process spawning encoded PowerShell

A Sysmon Process Creation record showed `w3wp.exe` launching `powershell.exe` under `IIS APPPOOL\DefaultAppPool` with `-nop -noni -enc` arguments.

- **Triage significance:** Potential unauthorized script execution in an IIS application context.
- **MITRE ATT&CK:** [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/); [T1027 — Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/) as a candidate.
- **Evidence limitation:** Web exploitation, the final payload's behavior, and compromise were not independently established.

![IIS to PowerShell evidence](screenshots/04-iis-powershell-process-chain.png)

### 3. Suspicious PowerShell credential prompt

PowerShell Script Block Logging captured a function using `PromptForCredential`, `GetNetworkCredential().Password`, and `ValidateCredentials`.

- **Triage significance:** Potential credential collection requiring follow-up.
- **MITRE ATT&CK:** [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/).
- **Evidence limitation:** No proof that a user entered a password or that any credentials were exfiltrated.

![Credential prompt evidence](screenshots/07-powershell-credential-prompt.png)

A separate 4104 event included Base64/GZip decoding behavior. Without sufficient host and session identifiers, it cannot be reliably joined to the other findings.

## SPL investigation examples

**Validate ingestion**

```spl
index=soc_lab1
| stats count by source, EventID
```

**Review process creation**

```spl
index=soc_lab1 EventID=1
| table _time Computer User Image CommandLine ParentImage
| sort 0 _time
```

**Inspect IIS-spawned PowerShell**

```spl
index=soc_lab1 EventID=1 Image="*powershell.exe"
| table _time User ParentImage Image ParentCommandLine CommandLine
```

**Identify suspicious credential prompts**

```spl
index=soc_lab1 EventID=4104
| search ScriptBlockText="*PromptForCredential*"
| table _time ScriptBlockText
```

The tested searches and detection categories are documented in [`detections/soc-detection-queries.spl`](detections/soc-detection-queries.spl). These are **lab triage searches**, not production-ready alert rules; production deployment would require contextual enrichment, tuning, and false-positive analysis.

## Evidence and investigation workflow

The workflow followed these stages: import CSV events into an **Events** index; validate field extraction and event counts; examine process ancestry and PowerShell content; investigate potential credential-access behavior; reconstruct a timestamp-ordered view; summarize detection matches; and record limitations and remediation recommendations.

![Ingestion verification](screenshots/02-ingestion-validation.png)

![Detection summary](screenshots/09-detection-summary.png)

See the [full investigation timeline](screenshots/08-soc-investigation-timeline.png) and the complete report for additional supporting evidence. Timestamps are shown as displayed by Splunk; their original timezone should be verified before using them for cross-system correlation.

## Documentation

- **[Full SOC Investigation Report](reports/SOC-Investigation-Report.md)** — findings, evidence, chronology, ATT&CK mapping, and limitations.
- **[Methodology](methodology.md)** — lab procedure and investigative approach.
- **[Remediation](remediation.md)** — defensive recommendations and follow-up validation.
- **[Detection Queries](detections/soc-detection-queries.spl)** — reusable example SPL searches.
- **[Screenshots](screenshots/)** — nine UI evidence images.

## Repository structure

```text
splunk-soc-investigation-lab/
├── README.md
├── methodology.md
├── remediation.md
├── datasets/
├── detections/
│   └── soc-detection-queries.spl
├── reports/
│   └── SOC-Investigation-Report.md
├── screenshots/
│   ├── 01-lsass-process-access.png
│   ├── ...
│   └── 09-detection-summary.png
├── scripts/
└── searches/
```

## Lessons learned

- Correct event-index configuration and timestamp interpretation are essential for reliable analysis.
- Parent-child relationships, command-line switches, and script block contents make useful investigation pivots.
- A detection match is an investigative lead—not proof of successful attack execution.
- Cross-dataset attribution requires common host/session/process identifiers; event proximity alone is insufficient.

**Purpose:** Demonstrate a structured, evidence-based SOC analyst workflow suitable for a cybersecurity portfolio. No live compromise or enterprise incident response is claimed.
