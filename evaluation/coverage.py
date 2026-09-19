import logging
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class TechniqueCoverage:
    technique_id: str
    technique_name: str
    total_tests: int
    tests_with_telemetry: int
    tests_with_rules: int
    tests_detected: int
    detection_rate: float
    rules: list = None
    gaps: list = None

    def __post_init__(self):
        if self.rules is None:
            self.rules = []
        if self.gaps is None:
            self.gaps = []


class CoverageAnalyzer:
    TECHNIQUE_INFO = {
        "T1003.001": "OS Credential Dumping: LSASS Memory",
        "T1003.008": "OS Credential Dumping: /etc/passwd and /etc/shadow",
        "T1059.001": "Command and Scripting Interpreter: PowerShell",
        "T1059.003": "Command and Scripting Interpreter: Windows Command Shell",
        "T1105": "Ingress Tool Transfer",
        "T1055": "Process Injection",
        "T1070.004": "Indicator Removal: File Deletion",
    }

    def __init__(self, evaluation_dir: str):
        self.evaluation_dir = Path(evaluation_dir)

    def analyze(self) -> list[TechniqueCoverage]:
        eval_files = list(self.evaluation_dir.glob("eval_*.json"))
        if not eval_files:
            logger.warning("No evaluation results found")
            return []

        by_technique = {}
        for eval_file in eval_files:
            with open(eval_file) as f:
                data = json.load(f)

            tech_id = data["technique_id"]
            if tech_id not in by_technique:
                by_technique[tech_id] = {
                    "results": [],
                    "rules": set(),
                    "telemetry_files": set()
                }
            by_technique[tech_id]["results"].append(data)
            by_technique[tech_id]["rules"].add(data["rule_file"])
            by_technique[tech_id]["telemetry_files"].add(data["telemetry_file"])

        coverage = []
        for tech_id, data in by_technique.items():
            results = data["results"]
            total_tests = len(set(r["test_guid"] for r in results))
            tests_with_telemetry = len(data["telemetry_files"])
            tests_with_rules = len(data["rules"])
            tests_detected = sum(1 for r in results if r["passed"])

            detection_rate = tests_detected / total_tests if total_tests > 0 else 0.0

            gaps = self._identify_gaps(tech_id, results)

            coverage.append(TechniqueCoverage(
                technique_id=tech_id,
                technique_name=self.TECHNIQUE_INFO.get(tech_id, tech_id),
                total_tests=total_tests,
                tests_with_telemetry=tests_with_telemetry,
                tests_with_rules=tests_with_rules,
                tests_detected=tests_detected,
                detection_rate=detection_rate,
                rules=list(data["rules"]),
                gaps=gaps
            ))

        return coverage

    def _identify_gaps(self, technique_id: str, results: list) -> list[str]:
        gaps = []

        failed_results = [r for r in results if not r["passed"]]
        if failed_results:
            gaps.append(f"{len(failed_results)} test(s) produced telemetry but no rule match")

        no_telemetry = [r for r in results if r["total_events"] == 0]
        if no_telemetry:
            gaps.append(f"{len(no_telemetry)} test(s) produced NO telemetry - collection gap")

        if technique_id in ["T1055", "T1003.001"]:
            if not any("process_access" in str(r.get("match_details", [])).lower() for r in results):
                gaps.append("HYPOTHESIS: Process injection (T1055) may need Sysmon Event ID 10 (ProcessAccess) - verify collection")

        if technique_id == "T1105":
            if not any("network" in str(r.get("match_details", [])).lower() for r in results):
                gaps.append("HYPOTHESIS: Ingress tool transfer (T1105) may need network telemetry (Zeek/PCAP) - verify collection")

        return gaps

    def print_summary(self, coverage: list[TechniqueCoverage]):
        print("\n" + "=" * 80)
        print("COVERAGE ANALYSIS SUMMARY")
        print("=" * 80)
        print(f"{'Technique':<20} {'Name':<50} {'Tests':<6} {'Telemetry':<10} {'Rules':<6} {'Detected':<9} {'Rate':<8}")
        print("-" * 80)

        for c in coverage:
            print(f"{c.technique_id:<20} {c.technique_name[:48]:<50} {c.total_tests:<6} "
                  f"{c.tests_with_telemetry:<10} {c.tests_with_rules:<6} {c.tests_detected:<9} {c.detection_rate:.1%}")

        print("-" * 80)
        total_techniques = len(coverage)
        detected_techniques = sum(1 for c in coverage if c.detection_rate > 0)
        print(f"Techniques with >=1 detection: {detected_techniques}/{total_techniques}")

        print("\nGAPS IDENTIFIED:")
        for c in coverage:
            if c.gaps:
                print(f"\n  {c.technique_id} ({c.technique_name}):")
                for gap in c.gaps:
                    print(f"    - {gap}")

    def export_json(self, coverage: list[TechniqueCoverage], output_path: Path):
        with open(output_path, "w") as f:
            json.dump([c.__dict__ for c in coverage], f, indent=2)
        logger.info(f"Coverage report saved to {output_path}")