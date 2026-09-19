import argparse
import logging
import sys
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from orchestration.orchestrator import PipelineOrchestrator
from telemetry.normalizer import TelemetryNormalizer
from detection.drafter import SigmaDrafter
from evaluation.evaluator import RuleEvaluator
from evaluation.coverage import CoverageAnalyzer
from review.reviewer import RuleReviewer
import yaml


def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )


def load_config(config_path: str) -> dict:
    with open(config_path) as f:
        if config_path.endswith(".yaml") or config_path.endswith(".yml"):
            config = yaml.safe_load(f)
        else:
            import json
            config = json.load(f)

    for key, value in config.items():
        if isinstance(value, str) and value.startswith("{{ env.") and value.endswith(" }}"):
            env_var = value[8:-3]
            config[key] = os.environ.get(env_var, "")
    return config


def cmd_run(args):
    config = load_config(args.config)
    orchestrator = PipelineOrchestrator(config)

    if args.technique:
        orchestrator.run_single_technique(args.technique, args.vm_index)
    else:
        orchestrator.run_full_pipeline()


def cmd_normalize(args):
    normalizer = TelemetryNormalizer()
    events = normalizer.normalize_directory(Path(args.telemetry_dir))
    print(f"Normalized {len(events)} events")
    for e in events[:5]:
        print(f"  {e.timestamp} | {e.event_type} | {e.process_name} | {e.command_line}")


def cmd_draft(args):
    config = load_config(args.config)
    normalizer = TelemetryNormalizer()
    drafter = SigmaDrafter(config["detection"].get("rule_template"), config["detection"].get("min_confidence", "low"))

    telemetry_dir = Path(config["telemetry"]["output_dir"])
    rules_dir = Path(config["detection"]["output_dir"])

    for tech_dir in telemetry_dir.iterdir():
        if not tech_dir.is_dir():
            continue

        technique_id = tech_dir.name.split("_")[0] if "_" in tech_dir.name else tech_dir.name
        events = normalizer.normalize_directory(tech_dir)

        if not events:
            print(f"No events for {technique_id}, skipping")
            continue

        test_guid = tech_dir.name.split("_")[1] if "_" in tech_dir.name else "unknown"
        rule = drafter.draft_from_events(events, technique_id, test_guid)
        drafter.save_rule(rule, rules_dir)


def cmd_evaluate(args):
    config = load_config(args.config)
    evaluator = RuleEvaluator(
        config["evaluation"]["rules_dir"],
        config["evaluation"]["telemetry_dir"],
        config["evaluation"]["output_dir"],
        config["evaluation"].get("sigma_backend", "sigmac")
    )
    results = evaluator.evaluate_all()
    print(f"Evaluated {len(results)} rule/telemetry pairs")

    analyzer = CoverageAnalyzer(config["evaluation"]["output_dir"])
    coverage = analyzer.analyze()
    analyzer.print_summary(coverage)
    analyzer.export_json(coverage, Path(config["evaluation"]["output_dir"]) / "coverage_report.json")


def cmd_review(args):
    config = load_config(args.config)
    reviewer = RuleReviewer(
        config["evaluation"]["rules_dir"],
        config["evaluation"]["telemetry_dir"]
    )
    reviews = reviewer.review_all_misses()
    print(f"Reviewed {len(reviews)} missed detections")


def cmd_pipeline(args):
    config = load_config(args.config)
    print("=== STAGE 1: RUN TECHNIQUES ===")
    orchestrator = PipelineOrchestrator(config)
    orchestrator.run_full_pipeline()

    print("\n=== STAGE 2: DRAFT RULES ===")
    normalizer = TelemetryNormalizer()
    drafter = SigmaDrafter(config["detection"].get("rule_template"), config["detection"].get("min_confidence", "low"))

    telemetry_dir = Path(config["telemetry"]["output_dir"])
    rules_dir = Path(config["detection"]["output_dir"])

    for tech_dir in telemetry_dir.iterdir():
        if not tech_dir.is_dir():
            continue
        technique_id = tech_dir.name.split("_")[0] if "_" in tech_dir.name else tech_dir.name
        events = normalizer.normalize_directory(tech_dir)
        if not events:
            continue
        test_guid = tech_dir.name.split("_")[1] if "_" in tech_dir.name else "unknown"
        rule = drafter.draft_from_events(events, technique_id, test_guid)
        drafter.save_rule(rule, rules_dir)

    print("\n=== STAGE 3: EVALUATE ===")
    evaluator = RuleEvaluator(
        config["evaluation"]["rules_dir"],
        config["evaluation"]["telemetry_dir"],
        config["evaluation"]["output_dir"],
        config["evaluation"].get("sigma_backend", "sigmac")
    )
    evaluator.evaluate_all()

    print("\n=== STAGE 4: COVERAGE ANALYSIS ===")
    analyzer = CoverageAnalyzer(config["evaluation"]["output_dir"])
    coverage = analyzer.analyze()
    analyzer.print_summary(coverage)
    analyzer.export_json(coverage, Path(config["evaluation"]["output_dir"]) / "coverage_report.json")

    print("\n=== STAGE 5: REVIEW MISSES ===")
    reviewer = RuleReviewer(
        config["evaluation"]["rules_dir"],
        config["evaluation"]["telemetry_dir"]
    )
    reviewer.review_all_misses()


def main():
    parser = argparse.ArgumentParser(description="Purple Team Research Pipeline")
    parser.add_argument("-c", "--config", default="config/default.yaml", help="Config file path")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="Execute Atomic techniques against lab VMs")
    run_parser.add_argument("-t", "--technique", help="Specific technique ID (e.g., T1003.001)")
    run_parser.add_argument("--vm-index", type=int, default=0, help="VM index from config")

    norm_parser = subparsers.add_parser("normalize", help="Normalize telemetry to common schema")
    norm_parser.add_argument("telemetry_dir", help="Directory containing raw telemetry")

    draft_parser = subparsers.add_parser("draft", help="Draft Sigma rules from telemetry")

    eval_parser = subparsers.add_parser("evaluate", help="Evaluate rules against telemetry")

    review_parser = subparsers.add_parser("review", help="Review missed detections")

    pipeline_parser = subparsers.add_parser("pipeline", help="Run full pipeline end-to-end")

    args = parser.parse_args()
    setup_logging(args.verbose)

    commands = {
        "run": cmd_run,
        "normalize": cmd_normalize,
        "draft": cmd_draft,
        "evaluate": cmd_evaluate,
        "review": cmd_review,
        "pipeline": cmd_pipeline,
    }

    commands[args.command](args)


if __name__ == "__main__":
    main()