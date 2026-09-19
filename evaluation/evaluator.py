import logging
import subprocess
import json
import yaml
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional
from telemetry.normalizer import NormalizedEvent, TelemetryNormalizer

logger = logging.getLogger(__name__)


@dataclass
class EvaluationResult:
    rule_file: str
    technique_id: str
    test_guid: str
    telemetry_file: str
    total_events: int
    matched_events: int
    match_details: list = None
    detection_rate: float = 0.0
    passed: bool = False

    def __post_init__(self):
        if self.match_details is None:
            self.match_details = []
        self.detection_rate = self.matched_events / self.total_events if self.total_events > 0 else 0.0
        self.passed = self.matched_events > 0


class SigmaBackend:
    def __init__(self, backend: str = "sigmac"):
        self.backend = backend

    def compile(self, rule_path: Path, target: str = "splunk") -> Optional[str]:
        if self.backend == "sigmac":
            return self._compile_sigmac(rule_path, target)
        elif self.backend == "pysigma":
            return self._compile_pysigma(rule_path, target)
        return None

    def _compile_sigmac(self, rule_path: Path, target: str) -> Optional[str]:
        try:
            result = subprocess.run(
                ["sigmac", "-t", target, str(rule_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                return result.stdout
            logger.error(f"sigmac failed: {result.stderr}")
            return None
        except FileNotFoundError:
            logger.error("sigmac not found in PATH")
            return None
        except subprocess.TimeoutExpired:
            logger.error("sigmac timeout")
            return None

    def _compile_pysigma(self, rule_path: Path, target: str) -> Optional[str]:
        try:
            from sigma.pipelines import get_pipeline
            from sigma.collection import SigmaCollection
            from sigma.backends import get_backend

            with open(rule_path) as f:
                rule_yaml = f.read()

            pipeline = get_pipeline(target)
            backend = get_backend(target)(pipeline)
            collection = SigmaCollection.from_yaml(rule_yaml)
            return backend.generate(collection)
        except Exception as e:
            logger.error(f"pysigma failed: {e}")
            return None


class RuleEvaluator:
    def __init__(self, rules_dir: str, telemetry_dir: str, output_dir: str, sigma_backend: str = "sigmac"):
        self.rules_dir = Path(rules_dir)
        self.telemetry_dir = Path(telemetry_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.sigma_backend = SigmaBackend(sigma_backend)
        self.normalizer = TelemetryNormalizer()

    def evaluate_rule(self, rule_path: Path, telemetry_path: Path) -> EvaluationResult:
        technique_id = rule_path.stem.split("_")[0] if "_" in rule_path.stem else "unknown"
        test_guid = rule_path.stem.split("_")[1] if "_" in rule_path.stem else "unknown"

        query = self.sigma_backend.compile(rule_path)
        if not query:
            return EvaluationResult(
                rule_file=str(rule_path),
                technique_id=technique_id,
                test_guid=test_guid,
                telemetry_file=str(telemetry_path),
                total_events=0,
                matched_events=0,
                passed=False
            )

        events = self._load_telemetry(telemetry_path)
        total_events = len(events)

        matched = self._execute_query(query, events)

        result = EvaluationResult(
            rule_file=str(rule_path),
            technique_id=technique_id,
            test_guid=test_guid,
            telemetry_file=str(telemetry_path),
            total_events=total_events,
            matched_events=len(matched),
            match_details=matched[:10]
        )

        self._save_result(result)
        return result

    def evaluate_all(self) -> list[EvaluationResult]:
        results = []
        rule_files = list(self.rules_dir.glob("*.yml"))

        for rule_file in rule_files:
            technique_id = rule_file.stem.split("_")[0]
            telemetry_files = list(self.telemetry_dir.glob(f"**/*{technique_id}*"))

            if not telemetry_files:
                logger.warning(f"No telemetry found for {technique_id}")
                continue

            for telemetry_file in telemetry_files:
                result = self.evaluate_rule(rule_file, telemetry_file)
                results.append(result)
                logger.info(f"Evaluated {rule_file.name} vs {telemetry_file.name}: "
                           f"{result.matched_events}/{result.total_events} matched")

        return results

    def _load_telemetry(self, telemetry_path: Path) -> list[NormalizedEvent]:
        if telemetry_path.is_dir():
            return self.normalizer.normalize_directory(telemetry_path)
        else:
            source_type = self.normalizer._detect_source_type(telemetry_path)
            if source_type:
                return self.normalizer.normalize_file(telemetry_path, source_type)
        return []

    def _execute_query(self, query: str, events: list[NormalizedEvent]) -> list[dict]:
        matched = []
        for event in events:
            if self._match_event(query, event):
                matched.append({
                    "timestamp": event.timestamp,
                    "event_id": event.event_id,
                    "event_type": event.event_type,
                    "process_name": event.process_name,
                    "command_line": event.command_line
                })
        return matched

    def _match_event(self, query: str, event: NormalizedEvent) -> bool:
        query_lower = query.lower()
        event_dict = event.to_dict()

        for field, value in event_dict.items():
            if value and str(value).lower() in query_lower:
                return True
        return False

    def _save_result(self, result: EvaluationResult):
        output_file = self.output_dir / f"eval_{result.technique_id}_{result.test_guid}.json"
        with open(output_file, "w") as f:
            json.dump(asdict(result), f, indent=2)