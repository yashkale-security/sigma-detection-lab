import logging
import yaml
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from telemetry.normalizer import NormalizedEvent, TelemetryNormalizer

logger = logging.getLogger(__name__)


@dataclass
class ReviewResult:
    rule_file: str
    technique_id: str
    test_guid: str
    fired: bool
    matched_field: Optional[str] = None
    matched_value: Optional[str] = None
    missing_fields: list = None
    suggested_changes: list = None
    confidence_adjustment: str = "none"

    def __post_init__(self):
        if self.missing_fields is None:
            self.missing_fields = []
        if self.suggested_changes is None:
            self.suggested_changes = []


class RuleReviewer:
    def __init__(self, rules_dir: str, telemetry_dir: str):
        self.rules_dir = Path(rules_dir)
        self.telemetry_dir = Path(telemetry_dir)
        self.normalizer = TelemetryNormalizer()

    def review_missed_detection(self, rule_path: Path, telemetry_path: Path) -> ReviewResult:
        technique_id = rule_path.stem.split("_")[0]
        test_guid = rule_path.stem.split("_")[1] if "_" in rule_path.stem else "unknown"

        rule = self._load_rule(rule_path)
        events = self._load_telemetry(telemetry_path)

        if not events:
            return ReviewResult(
                rule_file=str(rule_path),
                technique_id=technique_id,
                test_guid=test_guid,
                fired=False,
                missing_fields=["NO TELEMETRY CAPTURED"],
                suggested_changes=["Verify telemetry collection configuration for this technique"]
            )

        match_result = self._check_rule_match(rule, events)

        if match_result["fired"]:
            return ReviewResult(
                rule_file=str(rule_path),
                technique_id=technique_id,
                test_guid=test_guid,
                fired=True,
                matched_field=match_result["field"],
                matched_value=match_result["value"]
            )

        missing = self._identify_missing_fields(rule, events)
        suggestions = self._generate_suggestions(rule, events, missing)

        return ReviewResult(
            rule_file=str(rule_path),
            technique_id=technique_id,
            test_guid=test_guid,
            fired=False,
            missing_fields=missing,
            suggested_changes=suggestions,
            confidence_adjustment="lower" if len(events) > 5 else "insufficient_data"
        )

    def review_all_misses(self) -> list[ReviewResult]:
        results = []
        rule_files = list(self.rules_dir.glob("*.yml"))

        for rule_file in rule_files:
            technique_id = rule_file.stem.split("_")[0]
            telemetry_files = list(self.telemetry_dir.glob(f"**/*{technique_id}*"))

            for telemetry_file in telemetry_files:
                result = self.review_missed_detection(rule_file, telemetry_file)
                if not result.fired:
                    results.append(result)
                    self._log_review(result)

        return results

    def _load_rule(self, rule_path: Path) -> dict:
        with open(rule_path) as f:
            return yaml.safe_load(f)

    def _load_telemetry(self, telemetry_path: Path) -> list[NormalizedEvent]:
        if telemetry_path.is_dir():
            return self.normalizer.normalize_directory(telemetry_path)
        else:
            source_type = self.normalizer._detect_source_type(telemetry_path)
            if source_type:
                return self.normalizer.normalize_file(telemetry_path, source_type)
        return []

    def _check_rule_match(self, rule: dict, events: list[NormalizedEvent]) -> dict:
        detection = rule.get("detection", {})
        selection = detection.get("selection", {})
        condition = detection.get("condition", "selection")

        for event in events:
            if self._evaluate_condition(event, selection, condition):
                for field, value in selection.items():
                    if self._field_matches(event, field, value):
                        return {"fired": True, "field": field, "value": value}

        return {"fired": False}

    def _evaluate_condition(self, event: NormalizedEvent, selection: dict, condition: str) -> bool:
        if condition == "selection":
            return all(self._field_matches(event, field, value) for field, value in selection.items())
        elif condition == "selection or ...":
            return any(self._field_matches(event, field, value) for field, value in selection.items())
        elif condition.startswith("1 of "):
            return True
        return False

    def _field_matches(self, event: NormalizedEvent, field: str, value) -> bool:
        event_val = getattr(event, field, None)
        if event_val is None:
            return False

        if isinstance(value, list):
            return any(str(v).lower() in str(event_val).lower() for v in value)
        return str(value).lower() in str(event_val).lower()

    def _identify_missing_fields(self, rule: dict, events: list[NormalizedEvent]) -> list[str]:
        detection = rule.get("detection", {})
        selection = detection.get("selection", {})

        missing = []
        for field in selection.keys():
            found = any(getattr(e, field, None) is not None for e in events)
            if not found:
                missing.append(f"{field} (required by rule but absent in all {len(events)} events)")

        return missing

    def _generate_suggestions(self, rule: dict, events: list[NormalizedEvent], missing: list) -> list[str]:
        suggestions = []

        if missing:
            suggestions.append("Consider broadening rule to use fields actually present in telemetry")
            present_fields = set()
            for e in events:
                for f in ["process_name", "command_line", "image_path", "parent_process_name", "target_path", "user"]:
                    if getattr(e, f, None):
                        present_fields.add(f)
            if present_fields:
                suggestions.append(f"Available fields in telemetry: {', '.join(sorted(present_fields))}")

        event_types = set(e.event_type for e in events)
        rule_event_types = set()
        for field in rule.get("detection", {}).get("selection", {}):
            if "eventid" in field.lower() or "event_id" in field.lower():
                rule_event_types.update(rule["detection"]["selection"][field])

        if event_types and not rule_event_types:
            suggestions.append(f"Observed event types not referenced in rule: {', '.join(event_types)}")

        return suggestions

    def _log_review(self, result: ReviewResult):
        logger.info(f"\n=== REVIEW: {result.technique_id} / {result.test_guid} ===")
        logger.info(f"Rule: {result.rule_file}")
        logger.info(f"Fired: {result.fired}")
        if result.missing_fields:
            logger.info(f"Missing fields: {result.missing_fields}")
        if result.suggested_changes:
            logger.info(f"Suggestions:")
            for s in result.suggested_changes:
                logger.info(f"  - {s}")