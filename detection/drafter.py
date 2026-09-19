import logging
import yaml
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional
from jinja2 import Template
from telemetry.normalizer import NormalizedEvent

logger = logging.getLogger(__name__)


@dataclass
class RuleDraft:
    technique_id: str
    technique_name: str
    test_guid: str
    title: str
    description: str
    logsource: dict
    detection: dict
    fields_used: list = field(default_factory=list)
    fields_assumed: list = field(default_factory=list)
    false_positive_scenarios: list = field(default_factory=list)
    confidence: str = "low"
    references: list = field(default_factory=list)
    tags: list = field(default_factory=list)
    generated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    rule_yaml: str = ""

    def to_sigma(self) -> str:
        return self.rule_yaml


class SigmaDrafter:
    TECHNIQUE_INFO = {
        "T1003.001": {"name": "OS Credential Dumping: LSASS Memory", "tactic": "credential-access"},
        "T1003.008": {"name": "OS Credential Dumping: /etc/passwd and /etc/shadow", "tactic": "credential-access"},
        "T1059.001": {"name": "Command and Scripting Interpreter: PowerShell", "tactic": "execution"},
        "T1059.003": {"name": "Command and Scripting Interpreter: Windows Command Shell", "tactic": "execution"},
        "T1105": {"name": "Ingress Tool Transfer", "tactic": "command-and-control"},
        "T1055": {"name": "Process Injection", "tactic": "defense-evasion"},
        "T1070.004": {"name": "Indicator Removal: File Deletion", "tactic": "defense-evasion"},
    }

    def __init__(self, template_path: str = None, min_confidence: str = "low"):
        self.min_confidence = min_confidence
        if template_path and Path(template_path).exists():
            with open(template_path) as f:
                self.template = Template(f.read())
        else:
            self.template = Template(SIGMA_TEMPLATE)

    def draft_from_events(self, events: list[NormalizedEvent], technique_id: str, test_guid: str) -> RuleDraft:
        if not events:
            logger.warning("No events provided for drafting")
            return self._empty_draft(technique_id, test_guid)

        tech_info = self.TECHNIQUE_INFO.get(technique_id, {"name": technique_id, "tactic": "unknown"})

        field_analysis = self._analyze_fields(events)
        detection_logic = self._build_detection(events, field_analysis)
        false_positives = self._estimate_false_positives(events, detection_logic)

        rule = RuleDraft(
            technique_id=technique_id,
            technique_name=tech_info["name"],
            test_guid=test_guid,
            title=f"Detect {tech_info['name']} ({technique_id})",
            description=f"Detection for {tech_info['name']} based on observed telemetry from Atomic test {test_guid}",
            logsource=self._infer_logsource(events),
            detection=detection_logic,
            fields_used=field_analysis["used"],
            fields_assumed=field_analysis["assumed"],
            false_positive_scenarios=false_positives,
            confidence=self._assess_confidence(len(events), len(false_positives)),
            references=[f"https://attack.mitre.org/techniques/{technique_id}/"],
            tags=[f"attack.{tech_info['tactic']}", f"attack.{technique_id.lower().replace('.', '_')}"]
        )

        rule.rule_yaml = self.template.render(rule=rule)
        return rule

    def _analyze_fields(self, events: list[NormalizedEvent]) -> dict:
        used = set()
        assumed = set()

        for event in events:
            if event.process_name:
                used.add("process_name")
            if event.command_line:
                used.add("command_line")
            if event.image_path:
                used.add("image_path")
            if event.parent_process_name:
                used.add("parent_process_name")
            if event.target_path:
                used.add("target_path")
            if event.network_dst_ip:
                used.add("network_dst_ip")
            if event.user:
                used.add("user")

        return {"used": list(used), "assumed": list(assumed)}

    def _build_detection(self, events: list[NormalizedEvent], field_analysis: dict) -> dict:
        conditions = []

        process_names = set(e.process_name for e in events if e.process_name)
        if process_names:
            conditions.append({"Image|endswith": list(process_names)})

        command_lines = set(e.command_line for e in events if e.command_line)
        if command_lines:
            conditions.append({"CommandLine|contains": list(command_lines)})

        parent_processes = set(e.parent_process_name for e in events if e.parent_process_name)
        if parent_processes:
            conditions.append({"ParentImage|endswith": list(parent_processes)})

        target_paths = set(e.target_path for e in events if e.target_path)
        if target_paths:
            conditions.append({"TargetFilename|contains": list(target_paths)})

        if not conditions:
            conditions.append({"EventID": list(set(e.event_id for e in events))})

        return {"selection": conditions, "condition": "selection"}

    def _estimate_false_positives(self, events: list[NormalizedEvent], detection: dict) -> list[str]:
        fps = []

        if "Image|endswith" in str(detection):
            fps.append("Legitimate administrative tools (e.g., rundll32.exe, powershell.exe) matching process name")

        if "CommandLine|contains" in str(detection):
            fps.append("Normal scripts or admin commands containing similar arguments")

        if "ParentImage|endswith" in str(detection):
            fps.append("Legitimate parent-child process relationships (e.g., explorer.exe spawning cmd.exe)")

        if not fps:
            fps.append("None identified from current telemetry sample")

        return fps

    def _assess_confidence(self, event_count: int, fp_count: int) -> str:
        if event_count >= 10 and fp_count <= 1:
            return "high"
        return "low"

    def _infer_logsource(self, events: list[NormalizedEvent]) -> dict:
        sources = set(e.source for e in events)
        if "sysmon" in sources:
            return {"product": "windows", "service": "sysmon"}
        elif "windows_event" in sources:
            return {"product": "windows", "service": "security"}
        elif "edr_json" in sources:
            return {"product": "edr", "service": "generic"}
        return {"product": "windows", "service": "sysmon"}

    def _empty_draft(self, technique_id: str, test_guid: str) -> RuleDraft:
        tech_info = self.TECHNIQUE_INFO.get(technique_id, {"name": technique_id, "tactic": "unknown"})
        return RuleDraft(
            technique_id=technique_id,
            technique_name=tech_info["name"],
            test_guid=test_guid,
            title=f"Detect {tech_info['name']} ({technique_id}) - NO TELEMETRY",
            description="No telemetry captured for this technique execution",
            logsource={"product": "windows", "service": "sysmon"},
            detection={"selection": {}, "condition": "never"},
            confidence="low",
            false_positive_scenarios=["Rule will never fire - no telemetry observed"]
        )

    def save_rule(self, rule: RuleDraft, output_dir: Path):
        output_dir.mkdir(parents=True, exist_ok=True)
        filename = f"{rule.technique_id}_{rule.test_guid}.yml"
        filepath = output_dir / filename
        with open(filepath, "w") as f:
            f.write(rule.rule_yaml)
        logger.info(f"Saved Sigma rule: {filepath}")
        return filepath