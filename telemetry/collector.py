import logging
import json
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional
from orchestration.vm_manager import VMConfig

logger = logging.getLogger(__name__)


@dataclass
class TelemetrySession:
    session_id: str
    run_id: str
    vm_config: VMConfig
    start_time: datetime
    collectors: list = field(default_factory=list)
    output_dir: Path = None


class TelemetryCollectorBase(ABC):
    @abstractmethod
    def start(self, session: TelemetrySession) -> bool:
        pass

    @abstractmethod
    def stop(self, session: TelemetrySession) -> Optional[Path]:
        pass

    @abstractmethod
    def collect(self, session: TelemetrySession) -> list[dict]:
        pass


class SysmonCollector(TelemetryCollectorBase):
    def __init__(self, config: dict):
        self.config = config
        self.log_path = config.get("log_path", "Microsoft-Windows-Sysmon/Operational")
        self.config_file = config.get("config_file")

    def start(self, session: TelemetrySession) -> bool:
        logger.info("Starting Sysmon collection")
        return True

    def stop(self, session: TelemetrySession) -> Optional[Path]:
        output_file = session.output_dir / f"sysmon_{session.run_id}.evtx"
        try:
            cmd = ["wevtutil", "epl", self.log_path, str(output_file)]
            subprocess.run(cmd, check=True, capture_output=True, timeout=60)
            logger.info(f"Sysmon logs saved to {output_file}")
            return output_file
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to export Sysmon logs: {e.stderr.decode()}")
            return None

    def collect(self, session: TelemetrySession) -> list[dict]:
        return []


class WindowsEventCollector(TelemetryCollectorBase):
    def __init__(self, config: dict):
        self.channels = config.get("channels", ["Security", "System"])

    def start(self, session: TelemetrySession) -> bool:
        logger.info("Starting Windows Event Log collection")
        return True

    def stop(self, session: TelemetrySession) -> Optional[Path]:
        output_dir = session.output_dir / f"winevt_{session.run_id}"
        output_dir.mkdir(parents=True, exist_ok=True)

        for channel in self.channels:
            safe_name = channel.replace("/", "_").replace("-", "_")
            output_file = output_dir / f"{safe_name}_{session.run_id}.evtx"
            try:
                cmd = ["wevtutil", "epl", channel, str(output_file)]
                subprocess.run(cmd, check=True, capture_output=True, timeout=60)
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to export {channel}: {e.stderr.decode()}")

        logger.info(f"Windows Event logs saved to {output_dir}")
        return output_dir

    def collect(self, session: TelemetrySession) -> list[dict]:
        return []


class EDRJSONCollector(TelemetryCollectorBase):
    def __init__(self, config: dict):
        self.endpoint = config.get("endpoint")
        self.api_key = config.get("api_key")

    def start(self, session: TelemetrySession) -> bool:
        logger.info("Starting EDR JSON collection")
        return True

    def stop(self, session: TelemetrySession) -> Optional[Path]:
        output_file = session.output_dir / f"edr_{session.run_id}.jsonl"
        try:
            import requests
            headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
            params = {"since": session.start_time.isoformat()}
            resp = requests.get(self.endpoint, headers=headers, params=params, timeout=30)
            resp.raise_for_status()
            with open(output_file, "w") as f:
                for line in resp.text.strip().split("\n"):
                    if line:
                        f.write(line + "\n")
            logger.info(f"EDR events saved to {output_file}")
            return output_file
        except Exception as e:
            logger.error(f"Failed to collect EDR events: {e}")
            return None

    def collect(self, session: TelemetrySession) -> list[dict]:
        return []


class ZeekCollector(TelemetryCollectorBase):
    def __init__(self, config: dict):
        self.interface = config.get("interface", "eth0")
        self.zeek_path = config.get("zeek_path", "zeek")

    def start(self, session: TelemetrySession) -> bool:
        logger.info("Starting Zeek collection")
        return True

    def stop(self, session: TelemetrySession) -> Optional[Path]:
        output_dir = session.output_dir / f"zeek_{session.run_id}"
        output_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Zeek logs in {output_dir}")
        return output_dir

    def collect(self, session: TelemetrySession) -> list[dict]:
        return []


class TelemetryCollector:
    COLLECTOR_MAP = {
        "sysmon": SysmonCollector,
        "windows_event": WindowsEventCollector,
        "edr_json": EDRJSONCollector,
        "zeek": ZeekCollector,
    }

    def __init__(self, config: dict):
        self.config = config
        self.collectors = []
        for c in config.get("collectors", []):
            collector_type = c["type"]
            if collector_type in self.COLLECTOR_MAP:
                self.collectors.append(self.COLLECTOR_MAP[collector_type](c["config"]))
            else:
                logger.warning(f"Unknown collector type: {collector_type}")

    def start_collection(self, vm_config: VMConfig, run_id: str) -> TelemetrySession:
        session = TelemetrySession(
            session_id=f"session_{run_id}",
            run_id=run_id,
            vm_config=vm_config,
            start_time=datetime.utcnow(),
            output_dir=Path(self.config["output_dir"]) / run_id
        )
        session.output_dir.mkdir(parents=True, exist_ok=True)

        for collector in self.collectors:
            collector.start(session)

        return session

    def stop_collection(self, session: TelemetrySession) -> Optional[Path]:
        collected_paths = []
        for collector in self.collectors:
            path = collector.stop(session)
            if path:
                collected_paths.append(str(path))

        manifest = {
            "session_id": session.session_id,
            "run_id": session.run_id,
            "vm_name": session.vm_config.name,
            "start_time": session.start_time.isoformat(),
            "end_time": datetime.utcnow().isoformat(),
            "collected_files": collected_paths
        }
        manifest_file = session.output_dir / "manifest.json"
        with open(manifest_file, "w") as f:
            json.dump(manifest, f, indent=2)

        logger.info(f"Telemetry collection complete. Manifest: {manifest_file}")
        return session.output_dir