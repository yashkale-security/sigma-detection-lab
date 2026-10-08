# Project Synopsis: Purple Team Research Pipeline

## 1. Problem Statement
Modern Security Operations Centers (SOCs) face a critical **detection engineering gap**: while MITRE ATT&CK provides a comprehensive framework of adversary techniques, translating these techniques into reliable, production-ready detection rules (Sigma) remains a manual, error-prone, and time-consuming process. Detection engineers must:
- Execute attack techniques in lab environments
- Manually analyze captured telemetry (Sysmon, Windows Event Logs, EDR)
- Hand-craft Sigma rules with proper field mappings
- Validate rules against real telemetry to measure detection rates and false positives
- Iterate on misses — a cycle that can take days per technique

This gap results in **incomplete detection coverage**, **high false positive rates**, and **slow response to emerging threats**.

## 2. Objectives
The Purple Team Research Pipeline automates the **end-to-end detection engineering lifecycle**:

| Objective | Description |
|-----------|-------------|
| **Automated Technique Execution** | Execute Atomic Red Team tests against instrumented lab VMs with snapshot-based reset |
| **Multi-Source Telemetry Collection** | Capture Sysmon, Windows Event Logs, EDR JSON, and Zeek network telemetry simultaneously |
| **Schema Normalization** | Convert heterogeneous log formats (EVTX, JSONL, EVTX) into a unified `NormalizedEvent` schema |
| **Sigma Rule Drafting** | Auto-generate Sigma rules from observed telemetry with field tracking (used vs. assumed) and confidence scoring |
| **Rule Evaluation** | Compile Sigma rules (sigmac/pysigma) and test against collected telemetry to compute detection rates |
| **Coverage Analysis** | Generate per-technique coverage reports with hypothesis gaps (collection vs. detection gaps) |
| **Miss Review Loop** | Analyze failed detections, identify missing fields, and suggest rule modifications |

## 3. Scope
### In Scope
- **Techniques**: 7 MITRE ATT&CK techniques (T1003.001, T1003.008, T1059.001, T1059.003, T1105, T1055, T1070.004)
- **Platform**: Windows 10/11 targets with Sysmon; extensible to Linux/macOS
- **Telemetry**: Sysmon (Event IDs 1,3,5-15,17-23,255), Windows Security/System/PowerShell/WMI logs, EDR JSON, Zeek
- **Output**: Sigma rules (YAML), evaluation results (JSON), coverage reports (JSON), review findings (logs)
- **Deployment**: VirtualBox VM management; extensible to VMware, libvirt, cloud

### Out of Scope
- Real-time production SIEM integration (rules exported for manual import)
- Automated rule deployment to production
- Adversary emulation beyond Atomic Red Team
- ML-based anomaly detection (rule-based only)

## 4. Proposed Methodology
The pipeline follows a **5-stage iterative workflow** aligned with the **Purple Teaming methodology**:

```
┌─────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  ORCHESTRATION  │────▶│   TELEMETRY      │────▶│   DETECTION      │
│  - VM Manager   │     │   - Collectors   │     │   - Sigma Drafter│
│  - Atomic Runner│     │   - Normalizers  │     │   - Templates    │
└─────────────────┘     └──────────────────┘     └────────┬─────────┘
                                                          │
┌─────────────────┐     ┌──────────────────┐             │
│    REVIEW       │◀────│  EVALUATION      │◀────────────┘
│  - Miss Analysis│     │  - Rule Evaluator│
│  - Suggestions  │     │  - Coverage      │
└─────────────────┘     └──────────────────┘
```

### Stage 1: Orchestration (`purple-pipeline run`)
- Revert VM to clean/telemetry snapshot via VirtualBox
- Execute Atomic Red Team tests via SSH (PowerShell, CMD, WMI)
- Handle dependencies and cleanup automatically

### Stage 2: Telemetry Collection & Normalization
- Collect logs via `wevtutil` (Sysmon, Windows Events), HTTP (EDR), Zeek (PCAP)
- Normalize to `NormalizedEvent` dataclass with 20+ standardized fields
- Auto-detect source type from filename patterns

### Stage 3: Sigma Rule Drafting (`purple-pipeline draft`)
- Analyze field frequency across events (used vs. assumed)
- Build detection logic: process names, command lines, parent-child relationships, target paths
- Estimate false positive scenarios from common admin activity
- Score confidence: `high` (≥10 events, ≤1 FP scenario) or `low`
- Render via Jinja2 template with MITRE tags, references, field metadata

### Stage 4: Evaluation & Coverage (`purple-pipeline evaluate`)
- Compile Sigma rules via `sigmac` (Splunk/Elastic/GCP backends) or `pysigma`
- Execute compiled queries against normalized events (substring matching fallback)
- Compute per-technique detection rate, telemetry coverage, rule coverage
- Identify hypothesis gaps: collection gaps (no telemetry) vs. detection gaps (telemetry but no match)

### Stage 5: Review & Iteration (`purple-pipeline review`)
- For each missed detection: exact field/value mismatch, missing required fields, available unused fields
- Suggest rule modifications: broaden field usage, add observed event types
- Confidence adjustment: lower confidence if telemetry exists but rule fails

## 5. Technology Stack
| Layer | Technologies |
|-------|--------------|
| **Language** | Python 3.10+ (dataclasses, type hints, asyncio-ready) |
| **VM Management** | VirtualBox (`VBoxManage`), Paramiko (SSH/SCP) |
| **Atomic Execution** | Atomic Red Team (YAML test definitions) |
| **Log Parsing** | `python-evtx` (EVTX→JSON), `wevtutil` (Windows native) |
| **Rule Format** | Sigma (YAML), Jinja2 templates |
| **Rule Compilation** | `sigmac` (Go) or `pysigma` (Python) |
| **Configuration** | YAML with environment variable substitution (`{{ env.VAR }}`) |
| **Output** | JSON (evaluation, coverage), YAML (Sigma rules), structured logs |

## 6. Key Innovations
1. **Field Provenance Tracking**: Every Sigma rule documents which fields were *observed in telemetry* vs. *assumed* — critical for auditability
2. **Confidence Scoring**: Quantitative threshold (≥10 events, ≤1 FP) replaces subjective judgment
3. **Hypothesis Gaps**: Coverage report distinguishes "no telemetry collected" (collection gap) from "telemetry exists but rule missed" (detection gap) with specific hypotheses (e.g., T1055 needs Sysmon Event ID 10)
4. **Review Loop Automation**: Automated miss analysis produces actionable suggestions (missing fields, available alternatives)
5. **Snapshot-Based Lab**: VM snapshot revert ensures clean, repeatable execution per technique

## 7. Expected Outcomes
| Deliverable | Format | Assessment Mapping |
|-------------|--------|-------------------|
| Pipeline CLI | Executable Python package | Prototype (10 marks) |
| Sigma Rules (7 techniques) | `data/rules/*.yml` | Prototype + Documentation |
| Coverage Report | `data/evaluation/coverage_report.json` | Database Design + Documentation |
| UML Diagrams | Mermaid/PlantUML source | UML Design (20 marks) |
| ER Diagram | Mermaid source | Database Design (10 marks) |
| Requirements Spec | Markdown | Requirement Gathering (10 marks) |
| Project Synopsis | This document | Project Synopsis (10 marks) |

## 8. Domain Alignment (BSc Cyber Security)
- **Vulnerability Assessment**: Technique execution validates detection coverage gaps
- **Secure Authentication Systems**: Sysmon Event ID 4624/4625 logon analysis
- **Intrusion Detection Systems**: Sigma rule generation for SIEM deployment
- **Network/Application Security**: Zeek network telemetry, process command-line analysis
- **Tools**: Python, Sigma, Atomic Red Team, Sysmon, VirtualBox, MITRE ATT&CK

## 9. Timeline (Field Project Duration)
| Week | Milestone |
|------|-----------|
| 1-2 | Environment setup: Atomic Red Team, VMs, Sysmon, pipeline dependencies |
| 3-4 | Stage 1-2: Orchestration + Telemetry collection working end-to-end |
| 5-6 | Stage 3: Sigma drafting with field tracking and confidence scoring |
| 7-8 | Stage 4: Evaluation engine with sigmac/pysigma backends |
| 9-10 | Stage 5: Coverage analysis + Review loop + Gap hypotheses |
| 11-12 | Integration testing, documentation, demo preparation |
| 13-14 | Final presentation, viva preparation, documentation submission |

## 10. Success Criteria
- [ ] Pipeline executes all 7 techniques against lab VMs without manual intervention
- [ ] Telemetry captured for ≥80% of technique tests
- [ ] Sigma rules drafted for 100% of techniques with telemetry
- [ ] Coverage report identifies ≥3 hypothesis gaps with actionable hypotheses
- [ ] Review loop produces suggestions for ≥50% of missed detections
- [ ] All assessment deliverables (Synopsis, Requirements, DB Design, UML, Prototype, Documentation) complete