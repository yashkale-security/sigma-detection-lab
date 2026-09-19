# Purple Team Research Pipeline

A structured pipeline for executing ATT&CK techniques against lab environments, capturing telemetry, drafting Sigma detections, evaluating coverage, and iterating on misses.

## Architecture

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

## Pipeline Stages

| Stage | Command | Description |
|-------|---------|-------------|
| 1. Run | `purple-pipeline run` | Execute Atomic Red Team techniques against lab VMs |
| 2. Normalize | `purple-pipeline normalize` | Convert raw logs to common schema |
| 3. Draft | `purple-pipeline draft` | Generate Sigma rules from observed telemetry |
| 4. Evaluate | `purple-pipeline evaluate` | Test rules against telemetry, compute coverage |
| 5. Review | `purple-pipeline review` | Analyze misses, suggest rule improvements |
| All | `purple-pipeline pipeline` | Run full pipeline end-to-end |

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Configure your lab (edit config/default.yaml)
cp config/default.yaml config/local.yaml
# Edit config/local.yaml with your VM IPs, credentials, Atomic repo path

# Run full pipeline
python -m cli.pipeline -c config/local.yaml
```

## Configuration

Key configuration sections in `config/default.yaml`:

- **lab**: VM provider (VirtualBox/VMware/libvirt/cloud), VM definitions with snapshots
- **atomic**: Path to Atomic Red Team repo, technique IDs to execute
- **telemetry**: Collectors (Sysmon, Windows Event Logs, EDR JSON, Zeek), output directory
- **detection**: Sigma rule output directory, template, confidence threshold
- **evaluation**: Rules/telemetry directories, Sigma backend (sigmac/pysigma)

## Output Structure

```
data/
├── telemetry/
│   └── <run_id>/
│       ├── manifest.json
│       ├── sysmon_<run_id>.evtx
│       ├── winevt_<run_id>/
│       └── edr_<run_id>.jsonl
├── rules/
│   ├── T1003.001_<guid>.yml
│   └── ...
└── evaluation/
    ├── eval_T1003.001_<guid>.json
    └── coverage_report.json
```

## Sigma Rule Drafting

Rules are drafted with explicit tracking of:

- **Fields used**: Observed in actual telemetry
- **Fields assumed**: Inferred but not verified
- **False positive scenarios**: Concrete scenarios listed
- **Confidence**: `high` (>=10 events, <=1 FP scenario) or `low`

Example output:
```yaml
title: Detect OS Credential Dumping: LSASS Memory (T1003.001)
detection:
  selection:
    Image|endswith:
      - werfault.exe
      - comsvcs.dll
    CommandLine|contains:
      - -m 1 -p
  condition: selection
fields_used: [process_name, command_line]
fields_assumed: [target_path]
false_positives:
  - Legitimate crash dump generation by WER
confidence: low
```

## Coverage Analysis

The coverage report shows:
- Tests executed per technique
- Telemetry captured vs missing
- Rules drafted vs missing
- Detection rate per technique
- **Hypothesis gaps** (flagged, not confirmed):
  - T1055: "Process injection may need Sysmon Event ID 10"
  - T1105: "Ingress tool transfer may need network telemetry"

## Review Loop

For each missed detection, the reviewer outputs:
- Exact field/value that failed to match
- Fields required by rule but absent in telemetry
- Available fields in telemetry not used by rule
- Suggested rule modifications

## Requirements

- Python 3.10+
- VirtualBox/VMware/libvirt for VM management
- Atomic Red Team repository cloned locally
- Sysmon configured on Windows targets
- `sigmac` or `pysigma` for rule compilation

## Ethical Use

This pipeline is for **authorized security research only**. Only run against systems you own or have explicit permission to test. The pipeline executes real attack techniques — treat it as you would any red team tooling.