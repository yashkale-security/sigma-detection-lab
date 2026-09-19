import logging
import json
import uuid
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Optional
from orchestration.vm_manager import VMManager, VMConfig
from orchestration.atomic_runner import AtomicRunner, ExecutionResult
from telemetry.collector import TelemetryCollector

logger = logging.getLogger(__name__)


@dataclass
class RunMetadata:
    run_id: str
    timestamp: str
    technique_id: str
    test_guid: str
    vm_name: str
    vm_ip: str
    success: bool
    execution_time: float
    telemetry_path: Optional[str] = None
    rule_matches: Optional[list] = None


class PipelineOrchestrator:
    def __init__(self, config: dict):
        self.config = config
        self.vm_manager = VMManager(config["lab"]["provider"])
        self.atomic_runner = AtomicRunner(config["atomic"]["repo_path"], self.vm_manager)
        self.telemetry_collector = TelemetryCollector(config["telemetry"])
        self.vms = [VMConfig(**vm) for vm in config["lab"]["vms"]]
        self.output_dir = Path(config["telemetry"]["output_dir"])
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def run_single_technique(self, technique_id: str, vm_index: int = 0, extra_args: dict = None) -> list[RunMetadata]:
        vm_config = self.vms[vm_index]
        run_id = str(uuid.uuid4())[:8]
        timestamp = datetime.utcnow().isoformat() + "Z"

        logger.info(f"[{run_id}] Preparing VM {vm_config.name} for {technique_id}")
        if not self.vm_manager.prepare_vm(vm_config, use_telemetry_snapshot=True):
            logger.error(f"[{run_id}] VM preparation failed")
            return []

        logger.info(f"[{run_id}] Starting telemetry collection")
        telemetry_session = self.telemetry_collector.start_collection(vm_config, run_id)

        results = self.atomic_runner.run_technique(vm_config, technique_id, extra_args)

        logger.info(f"[{run_id}] Stopping telemetry collection")
        telemetry_path = self.telemetry_collector.stop_collection(telemetry_session)

        run_metadata = []
        for result in results:
            meta = RunMetadata(
                run_id=run_id,
                timestamp=timestamp,
                technique_id=technique_id,
                test_guid=result.test_guid,
                vm_name=vm_config.name,
                vm_ip=vm_config.ip,
                success=result.success,
                execution_time=result.execution_time,
                telemetry_path=telemetry_path
            )
            run_metadata.append(meta)
            self._save_run_metadata(meta)

        return run_metadata

    def run_technique_suite(self, technique_ids: list[str], vm_index: int = 0) -> list[RunMetadata]:
        all_metadata = []
        for tech_id in technique_ids:
            logger.info(f"=== Running technique suite: {tech_id} ===")
            metadata = self.run_single_technique(tech_id, vm_index)
            all_metadata.extend(metadata)
        return all_metadata

    def run_full_pipeline(self, technique_ids: list[str] = None) -> list[RunMetadata]:
        if technique_ids is None:
            technique_ids = self.config["atomic"]["techniques"]
        return self.run_technique_suite(technique_ids)

    def _save_run_metadata(self, meta: RunMetadata):
        meta_file = self.output_dir / f"run_{meta.run_id}_{meta.technique_id}_{meta.test_guid}.json"
        with open(meta_file, "w") as f:
            json.dump(asdict(meta), f, indent=2)