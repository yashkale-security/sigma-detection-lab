# Requirements Analysis: Purple Team Research Pipeline

## 1. Functional Requirements

### FR-01: Technique Execution
| ID | Requirement | Priority |
|----|-------------|----------|
| FR-01.1 | Execute Atomic Red Team tests against target VMs via SSH | Must |
| FR-01.2 | Support multiple executors: PowerShell, CMD, WMI, Bash | Must |
| FR-01.3 | Resolve test dependencies (prerequisite commands, package installs) | Must |
| FR-01.4 | Execute cleanup commands after each test | Must |
| FR-01.5 | Support single technique or full suite execution | Must |
| FR-01.6 | Parameterize commands with input arguments (#{arg}# placeholders) | Should |

### FR-02: VM Management
| ID | Requirement | Priority |
|----|-------------|----------|
| FR-02.1 | Revert VM to named snapshot (clean/telemetry) | Must |
| FR-02.2 | Start VM in headless mode | Must |
| FR-02.3 | Wait for SSH connectivity with timeout | Must |
| FR-02.4 | Execute remote commands via SSH with timeout | Must |
| FR-02.5 | Upload/download files via SCP | Must |
| FR-02.6 | Support VirtualBox provider (extensible to VMware, libvirt) | Must |

### FR-03: Telemetry Collection
| ID | Requirement | Priority |
|----|-------------|----------|
| FR-03.1 | Collect Sysmon logs via `wevtutil epl` | Must |
| FR-03.2 | Collect Windows Event Logs (Security, System, PowerShell, WMI) | Must |
| FR-03.3 | Collect EDR JSON events via HTTP API | Should |
| FR-03.4 | Collect Zeek network logs | Could |
| FR-03.5 | Generate manifest.json with collection metadata | Must |
| FR-03.6 | Organize output by run_id in `data/telemetry/<run_id>/` | Must |

### FR-04: Telemetry Normalization
| ID | Requirement | Priority |
|----|-------------|----------|
| FR-04.1 | Parse EVTX files to JSON via `python-evtx` | Must |
| FR-04.2 | Parse JSONL and JSON files | Must |
| FR-04.3 | Auto-detect source type from filename | Must |
| FR-04.4 | Normalize to `NormalizedEvent` schema (20+ fields) | Must |
| FR-04.5 | Map Sysmon Event IDs to semantic types (1→process_create, 10→process_access, etc.) | Must |
| FR-04.6 | Map Windows Security Event IDs (4624→logon, 4688→process_create, etc.) | Must |
| FR-04.7 | Handle hex/decimal Process IDs in Windows Events | Must |

### FR-05: Sigma Rule Drafting
| ID | Requirement | Priority |
|----|-------------|----------|
| FR-05.1 | Analyze field frequency across events (used vs assumed) | Must |
| FR-05.2 | Build detection logic: Image|endswith, CommandLine|contains, ParentImage|endswith, TargetFilename|contains | Must |
| FR-05.3 | Fallback to EventID-based detection if no rich fields | Must |
| FR-05.4 | Estimate false positive scenarios from common admin patterns | Must |
| FR-05.5 | Score confidence: high (≥10 events, ≤1 FP) / low (otherwise) | Must |
| FR-05.6 | Infer logsource from event sources (sysmon→windows/sysmon) | Must |
| FR-05.7 | Render Sigma YAML via Jinja2 template with MITRE tags | Must |
| FR-05.8 | Save rules to `data/rules/<technique>_<guid>.yml` | Must |

### FR-06: Rule Evaluation
| ID | Requirement | Priority |
|----|-------------|----------|
| FR-06.1 | Compile Sigma rules via `sigmac` (preferred) or `pysigma` | Must |
| FR-06.2 | Support multiple backends: Splunk, Elastic, GCP, etc. | Should |
| FR-06.3 | Execute compiled query against normalized events | Must |
| FR-06.4 | Substring matching fallback if compilation fails | Must |
| FR-06.5 | Compute detection rate (matched/total events) | Must |
| FR-06.6 | Save per-rule evaluation results to `data/evaluation/eval_*.json` | Must |

### FR-07: Coverage Analysis
| ID | Requirement | Priority |
|----|-------------|----------|
| FR-07.1 | Aggregate evaluation results by technique | Must |
| FR-07.2 | Compute: total_tests, tests_with_telemetry, tests_with_rules, tests_detected, detection_rate | Must |
| FR-07.3 | Identify collection gaps (tests with zero telemetry events) | Must |
| FR-07.4 | Identify detection gaps (telemetry exists but no rule match) | Must |
| FR-07.5 | Generate hypothesis gaps for known tricky techniques (T1055→EventID 10, T1105→network telemetry) | Must |
| FR-07.6 | Print summary table to console | Must |
| FR-07.7 | Export JSON report to `data/evaluation/coverage_report.json` | Must |

### FR-08: Miss Review Loop
| ID | Requirement | Priority |
|----|-------------|----------|
| FR-08.1 | Load Sigma rule YAML and parsed telemetry | Must |
| FR-08.2 | Evaluate rule condition (selection/OR/1-of) against events | Must |
| FR-08.3 | Identify missing fields (required by rule, absent in all events) | Must |
| FR-08.4 | Identify available unused fields in telemetry | Must |
| FR-08.5 | Identify observed event types not referenced in rule | Must |
| FR-08.6 | Generate actionable suggestions for rule modification | Must |
| FR-08.7 | Adjust confidence: lower / insufficient_data | Must |
| FR-08.8 | Log structured review output | Must |

### FR-09: Pipeline Orchestration
| ID | Requirement | Priority |
|----|-------------|----------|
| FR-09.1 | Run full pipeline end-to-end: run→draft→evaluate→coverage→review | Must |
| FR-09.2 | Load configuration from YAML with env var substitution | Must |
| FR-09.3 | CLI with subcommands: run, normalize, draft, evaluate, review, pipeline | Must |

---

## 2. Non-Functional Requirements

| ID | Requirement | Category | Metric |
|----|-------------|----------|--------|
| NFR-01 | Pipeline executes 7 techniques in <30 min (excluding VM boot) | Performance | <1800s |
| NFR-02 | Normalize 10,000 events in <10 seconds | Performance | <10s |
| NFR-03 | Draft Sigma rule in <1 second per technique | Performance | <1s |
| NFR-04 | Evaluate 1 rule against 1000 events in <5 seconds | Performance | <5s |
| NFR-05 | Configuration via YAML file (no code changes) | Usability | - |
| NFR-06 | Environment variable substitution in config (`{{ env.VAR }}`) | Security | - |
| NFR-07 | Structured logging (timestamp, level, component, message) | Observability | - |
| NFR-08 | Modular architecture: each stage independently runnable | Maintainability | - |
| NFR-09 | Type hints on all public functions/classes | Maintainability | 100% |
| NFR-10 | Extensible collector/normalizer/evaluator via registry pattern | Extensibility | - |
| NFR-11 | No hardcoded secrets; all via env vars or config | Security | - |
| NFR-12 | Ethical use warning displayed on startup | Compliance | - |

---

## 3. User Requirements

### Primary Users
| User Role | Goals | Key Workflows |
|-----------|-------|---------------|
| **Detection Engineer** | Build reliable Sigma rules efficiently | `pipeline` → review coverage → `review` misses → modify rules → re-evaluate |
| **SOC Analyst** | Validate detection coverage for specific techniques | `run -t T1003.001` → `draft` → `evaluate` → check detection_rate |
| **Purple Team Lead** | Measure overall detection posture | `pipeline` → coverage report → identify gaps → prioritize engineering |
| **Security Researcher** | Test custom techniques in lab | `run -t TXXXX.XXX` with custom Atomic tests |

### User Stories
1. **As a Detection Engineer**, I want to execute a technique and automatically get a draft Sigma rule so I can skip manual telemetry analysis.
2. **As a SOC Analyst**, I want to see detection rates per technique so I know which attacks we'd miss.
3. **As a Purple Team Lead**, I want hypothesis gaps (collection vs detection) so I can prioritize sensor deployment.
4. **As a Researcher**, I want to run a custom Atomic test and get immediate feedback on detectability.

---

## 4. Data Requirements

### Input Data
| Source | Format | Volume | Frequency |
|--------|--------|--------|-----------|
| Atomic Red Team repo | YAML (technique definitions) | ~300 techniques | Static (cloned) |
| VM Snapshots | VirtualBox snapshots | 2 per VM | Pre-created |
| Sysmon Config | XML | 1 file | Static |
| Environment Variables | Shell env | 2-3 vars (passwords, API keys) | Per deployment |

### Output Data
| Artifact | Format | Location | Schema |
|----------|--------|----------|--------|
| Run Metadata | JSON | `data/telemetry/run_<id>_<tech>_<guid>.json` | RunMetadata dataclass |
| Sysmon Logs | EVTX | `data/telemetry/<run_id>/sysmon_<run_id>.evtx` | Windows EVTX |
| Windows Events | EVTX | `data/telemetry/<run_id>/winevt_<run_id>/*.evtx` | Windows EVTX |
| EDR Events | JSONL | `data/telemetry/<run_id>/edr_<run_id>.jsonl` | Line-delimited JSON |
| Manifest | JSON | `data/telemetry/<run_id>/manifest.json` | TelemetrySession |
| Sigma Rules | YAML | `data/rules/<tech>_<guid>.yml` | Sigma spec + custom fields |
| Evaluation Results | JSON | `data/evaluation/eval_<tech>_<guid>.json` | EvaluationResult dataclass |
| Coverage Report | JSON | `data/evaluation/coverage_report.json` | TechniqueCoverage[] |

---

## 5. Interface Requirements

### CLI Interface
```bash
purple-pipeline run [-t TECHNIQUE] [--vm-index N] [-c CONFIG]
purple-pipeline normalize <telemetry_dir>
purple-pipeline draft [-c CONFIG]
purple-pipeline evaluate [-c CONFIG]
purple-pipeline review [-c CONFIG]
purple-pipeline pipeline [-c CONFIG]
```

### Configuration Interface (config/default.yaml)
```yaml
lab:
  provider: virtualbox
  vms:
    - name: win10-target
      ip: 192.168.56.101
      credentials:
        username: admin
        password: "{{ env.LAB_VM_PASSWORD }}"
      snapshot_clean: clean-baseline
      snapshot_telemetry: with-sysmon

atomic:
  repo_path: /opt/atomic-red-team
  techniques: [T1003.001, T1059.001, ...]

telemetry:
  collectors:
    - type: sysmon
      config: { config_file: configs/sysmon-config.xml, log_path: Microsoft-Windows-Sysmon/Operational }
    - type: windows_event
      config: { channels: [Security, System, Microsoft-Windows-PowerShell/Operational] }
  output_dir: data/telemetry

detection:
  output_dir: data/rules
  rule_template: templates/sigma-rule.yml.j2
  min_confidence: low

evaluation:
  rules_dir: data/rules
  telemetry_dir: data/telemetry
  output_dir: data/evaluation
  sigma_backend: sigmac
```

---

## 6. Constraints & Assumptions

### Constraints
- **Python 3.10+** required (dataclasses, pattern matching)
- **VirtualBox** must be installed with `VBoxManage` in PATH
- **Atomic Red Team** repo must be cloned locally
- **Target VMs** must have Sysmon installed and configured
- **SSH access** to VMs with key or password auth
- **sigmac** (Go) or **pysigma** (Python) for rule compilation

### Assumptions
- Lab environment is isolated (no production network access)
- VM snapshots exist: `clean-baseline` (pre-attack), `with-sysmon` (Sysmon running)
- Analyst has permission to execute attack techniques in lab
- Network allows SSH (22) and WinRM (5985) to target VMs
- Disk space: ~10 GB for telemetry retention (30 days default)

---

## 7. Traceability Matrix

| Requirement | Synopsis Section | Design Component | Test Case |
|-------------|------------------|------------------|-----------|
| FR-01.1 | Stage 1 | AtomicRunner.load_technique_tests | Execute T1003.001 test 1 |
| FR-02.1 | Stage 1 | VirtualBoxProvider.revert_snapshot | Revert to clean-baseline |
| FR-03.1 | Stage 2 | SysmonCollector.stop | Export Sysmon EVTX |
| FR-04.4 | Stage 2 | NormalizedEvent dataclass | Normalize sample EVTX |
| FR-05.1 | Stage 3 | SigmaDrafter._analyze_fields | Check fields_used populated |
| FR-05.5 | Stage 3 | SigmaDrafter._assess_confidence | ≥10 events → high |
| FR-06.1 | Stage 4 | SigmaBackend._compile_sigmac | Compile rule to Splunk |
| FR-07.3 | Stage 4 | CoverageAnalyzer._identify_gaps | Zero telemetry → collection gap |
| FR-08.3 | Stage 5 | RuleReviewer._identify_missing_fields | Field in rule not in events |
| FR-09.1 | All | PipelineOrchestrator.run_full_pipeline | End-to-end dry run |