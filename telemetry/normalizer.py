import logging
import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional
from xml.etree import ElementTree as ET

logger = logging.getLogger(__name__)


@dataclass
class NormalizedEvent:
    timestamp: str
    event_id: str
    event_type: str
    source: str
    host: str
    user: Optional[str] = None
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    parent_process_name: Optional[str] = None
    parent_process_id: Optional[int] = None
    command_line: Optional[str] = None
    image_path: Optional[str] = None
    target_path: Optional[str] = None
    network_dst_ip: Optional[str] = None
    network_dst_port: Optional[int] = None
    network_protocol: Optional[str] = None
    raw_event: dict = None
    technique_tags: list = None

    def to_dict(self) -> dict:
        return asdict(self)


class EventNormalizer(ABC):
    @abstractmethod
    def normalize(self, raw_event: dict, source_file: str) -> Optional[NormalizedEvent]:
        pass


class SysmonNormalizer(EventNormalizer):
    EVENT_MAP = {
        1: "process_create",
        3: "network_connect",
        5: "process_terminate",
        6: "driver_load",
        7: "image_load",
        8: "create_remote_thread",
        9: "raw_access_read",
        10: "process_access",
        11: "file_create",
        12: "registry_create",
        13: "registry_set",
        14: "registry_delete",
        15: "file_create_stream_hash",
        17: "pipe_created",
        18: "pipe_connected",
        19: "wmi_event_filter",
        20: "wmi_consumer",
        21: "wmi_binding",
        22: "dns_query",
        23: "file_delete",
        255: "error",
    }

    def normalize(self, raw_event: dict, source_file: str) -> Optional[NormalizedEvent]:
        event_id = str(raw_event.get("EventID") or raw_event.get("event_id", ""))
        if not event_id.isdigit():
            return None

        eid = int(event_id)
        event_type = self.EVENT_MAP.get(eid, f"sysmon_{eid}")

        data = raw_event.get("EventData", raw_event.get("data", {}))
        if isinstance(data, list):
            data = {item.get("@Name", item.get("Name", "")): item.get("#text", item.get("text", "")) for item in data}

        return NormalizedEvent(
            timestamp=raw_event.get("TimeCreated", {}).get("@SystemTime", raw_event.get("timestamp", datetime.utcnow().isoformat())),
            event_id=event_id,
            event_type=event_type,
            source="sysmon",
            host=raw_event.get("Computer", raw_event.get("computer", "")),
            user=data.get("User", data.get("TargetUserName")),
            process_name=data.get("Image", data.get("SourceImage")),
            process_id=self._parse_int(data.get("ProcessId", data.get("SourceProcessId"))),
            parent_process_name=data.get("ParentImage"),
            parent_process_id=self._parse_int(data.get("ParentProcessId")),
            command_line=data.get("CommandLine"),
            image_path=data.get("Image"),
            target_path=data.get("TargetFilename", data.get("TargetObject")),
            network_dst_ip=data.get("DestinationIp"),
            network_dst_port=self._parse_int(data.get("DestinationPort")),
            network_protocol=data.get("Protocol"),
            raw_event=raw_event
        )

    def _parse_int(self, val):
        if val is None:
            return None
        try:
            return int(val)
        except (ValueError, TypeError):
            return None


class WindowsEventNormalizer(EventNormalizer):
    SECURITY_EVENT_MAP = {
        4624: "logon",
        4625: "logon_failure",
        4634: "logoff",
        4647: "logoff_initiated",
        4672: "special_logon",
        4688: "process_create",
        4689: "process_terminate",
        4697: "service_install",
        4698: "scheduled_task_create",
        4700: "scheduled_task_enable",
        4701: "scheduled_task_disable",
        4702: "scheduled_task_update",
        4719: "audit_policy_change",
        4720: "user_create",
        4722: "user_enable",
        4723: "user_password_change",
        4724: "user_password_reset",
        4725: "user_disable",
        4726: "user_delete",
        4732: "group_member_add",
        4733: "group_member_remove",
        4740: "user_lockout",
        4768: "kerberos_tgt_request",
        4769: "kerberos_tgs_request",
        4776: "ntlm_auth",
        5140: "network_share_access",
        5145: "network_share_access_detailed",
    }

    def normalize(self, raw_event: dict, source_file: str) -> Optional[NormalizedEvent]:
        event_id = str(raw_event.get("EventID") or raw_event.get("event_id", ""))
        if not event_id.isdigit():
            return None

        eid = int(event_id)
        event_type = self.SECURITY_EVENT_MAP.get(eid, f"winevt_{eid}")

        data = raw_event.get("EventData", raw_event.get("data", {}))
        if isinstance(data, list):
            data = {item.get("@Name", item.get("Name", "")): item.get("#text", item.get("text", "")) for item in data}

        return NormalizedEvent(
            timestamp=raw_event.get("TimeCreated", {}).get("@SystemTime", raw_event.get("timestamp", datetime.utcnow().isoformat())),
            event_id=event_id,
            event_type=event_type,
            source="windows_event",
            host=raw_event.get("Computer", raw_event.get("computer", "")),
            user=data.get("TargetUserName", data.get("SubjectUserName")),
            process_name=data.get("NewProcessName", data.get("ImageFileName")),
            process_id=self._parse_int(data.get("NewProcessId", data.get("ProcessId"))),
            parent_process_name=data.get("ParentProcessName"),
            parent_process_id=self._parse_int(data.get("ParentProcessId")),
            command_line=data.get("CommandLine"),
            image_path=data.get("NewProcessName"),
            target_path=data.get("ObjectName", data.get("TargetFileName")),
            raw_event=raw_event
        )

    def _parse_int(self, val):
        if val is None:
            return None
        try:
            return int(val, 16) if isinstance(val, str) and val.startswith("0x") else int(val)
        except (ValueError, TypeError):
            return None


class EDRJSONNormalizer(EventNormalizer):
    def normalize(self, raw_event: dict, source_file: str) -> Optional[NormalizedEvent]:
        return NormalizedEvent(
            timestamp=raw_event.get("timestamp", raw_event.get("@timestamp", datetime.utcnow().isoformat())),
            event_id=str(raw_event.get("event_id", raw_event.get("event_type", "unknown"))),
            event_type=raw_event.get("event_type", "edr_event"),
            source="edr_json",
            host=raw_event.get("host", raw_event.get("hostname", "")),
            user=raw_event.get("user", raw_event.get("username")),
            process_name=raw_event.get("process_name", raw_event.get("image_name")),
            process_id=self._parse_int(raw_event.get("process_id", raw_event.get("pid"))),
            parent_process_name=raw_event.get("parent_process_name"),
            parent_process_id=self._parse_int(raw_event.get("parent_process_id", raw_event.get("ppid"))),
            command_line=raw_event.get("command_line", raw_event.get("cmdline")),
            image_path=raw_event.get("image_path"),
            target_path=raw_event.get("target_path", raw_event.get("file_path")),
            network_dst_ip=raw_event.get("dst_ip", raw_event.get("destination_ip")),
            network_dst_port=self._parse_int(raw_event.get("dst_port", raw_event.get("destination_port"))),
            network_protocol=raw_event.get("protocol"),
            raw_event=raw_event
        )

    def _parse_int(self, val):
        if val is None:
            return None
        try:
            return int(val)
        except (ValueError, TypeError):
            return None


class TelemetryNormalizer:
    NORMALIZERS = {
        "sysmon": SysmonNormalizer(),
        "windows_event": WindowsEventNormalizer(),
        "edr_json": EDRJSONNormalizer(),
    }

    def __init__(self):
        pass

    def normalize_file(self, file_path: Path, source_type: str) -> list[NormalizedEvent]:
        normalizer = self.NORMALIZERS.get(source_type)
        if not normalizer:
            logger.warning(f"No normalizer for source type: {source_type}")
            return []

        events = []
        try:
            if file_path.suffix == ".evtx":
                events = self._parse_evtx(file_path, normalizer, source_type)
            elif file_path.suffix == ".jsonl":
                events = self._parse_jsonl(file_path, normalizer, source_type)
            elif file_path.suffix == ".json":
                events = self._parse_json(file_path, normalizer, source_type)
        except Exception as e:
            logger.error(f"Failed to normalize {file_path}: {e}")

        return events

    def _parse_evtx(self, file_path: Path, normalizer: EventNormalizer, source_type: str) -> list[NormalizedEvent]:
        import subprocess
        events = []
        result = subprocess.run(["python3", "-m", "evtx", "dump", str(file_path)], capture_output=True, text=True)
        if result.returncode != 0:
            logger.error(f"evtx dump failed: {result.stderr}")
            return events

        for line in result.stdout.strip().split("\n"):
            if line.strip():
                try:
                    raw = json.loads(line)
                    normalized = normalizer.normalize(raw, str(file_path))
                    if normalized:
                        events.append(normalized)
                except json.JSONDecodeError:
                    continue
        return events

    def _parse_jsonl(self, file_path: Path, normalizer: EventNormalizer, source_type: str) -> list[NormalizedEvent]:
        events = []
        with open(file_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                    normalized = normalizer.normalize(raw, str(file_path))
                    if normalized:
                        events.append(normalized)
                except json.JSONDecodeError:
                    continue
        return events

    def _parse_json(self, file_path: Path, normalizer: EventNormalizer, source_type: str) -> list[NormalizedEvent]:
        with open(file_path) as f:
            data = json.load(f)
        if isinstance(data, list):
            events = []
            for raw in data:
                normalized = normalizer.normalize(raw, str(file_path))
                if normalized:
                    events.append(normalized)
            return events
        else:
            normalized = normalizer.normalize(data, str(file_path))
            return [normalized] if normalized else []

    def normalize_directory(self, dir_path: Path) -> list[NormalizedEvent]:
        all_events = []
        for file_path in dir_path.rglob("*"):
            if file_path.is_file():
                source_type = self._detect_source_type(file_path)
                if source_type:
                    all_events.extend(self.normalize_file(file_path, source_type))
        return all_events

    def _detect_source_type(self, file_path: Path) -> Optional[str]:
        name = file_path.name.lower()
        if "sysmon" in name:
            return "sysmon"
        elif any(x in name for x in ["security", "system", "powershell", "wmi", "winevt"]):
            return "windows_event"
        elif "edr" in name:
            return "edr_json"
        return None