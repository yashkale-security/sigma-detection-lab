import subprocess
import time
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class VMConfig:
    name: str
    ip: str
    os: str
    username: str
    password: str
    snapshot_clean: str
    snapshot_telemetry: str


class VMProvider(ABC):
    @abstractmethod
    def revert_snapshot(self, vm_name: str, snapshot_name: str) -> bool:
        pass

    @abstractmethod
    def start_vm(self, vm_name: str) -> bool:
        pass

    @abstractmethod
    def wait_for_ssh(self, ip: str, username: str, password: str, timeout: int = 120) -> bool:
        pass

    @abstractmethod
    def execute_remote(self, ip: str, username: str, password: str, command: str, timeout: int = 300) -> tuple[int, str, str]:
        pass

    @abstractmethod
    def copy_to_vm(self, ip: str, username: str, password: str, local_path: str, remote_path: str) -> bool:
        pass

    @abstractmethod
    def copy_from_vm(self, ip: str, username: str, password: str, remote_path: str, local_path: str) -> bool:
        pass


class VirtualBoxProvider(VMProvider):
    def __init__(self):
        self.vboxmanage = "VBoxManage"

    def revert_snapshot(self, vm_name: str, snapshot_name: str) -> bool:
        try:
            subprocess.run(
                [self.vboxmanage, "snapshot", vm_name, "restore", snapshot_name],
                check=True,
                capture_output=True,
                timeout=60
            )
            logger.info(f"Reverted {vm_name} to snapshot {snapshot_name}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to revert snapshot: {e.stderr.decode()}")
            return False

    def start_vm(self, vm_name: str) -> bool:
        try:
            subprocess.run(
                [self.vboxmanage, "startvm", vm_name, "--type", "headless"],
                check=True,
                capture_output=True,
                timeout=60
            )
            logger.info(f"Started VM {vm_name}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to start VM: {e.stderr.decode()}")
            return False

    def wait_for_ssh(self, ip: str, username: str, password: str, timeout: int = 120) -> bool:
        import paramiko
        import socket

        start = time.time()
        while time.time() - start < timeout:
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(ip, username=username, password=password, timeout=10)
                client.close()
                return True
            except (paramiko.SSHException, socket.error):
                time.sleep(5)
        return False

    def execute_remote(self, ip: str, username: str, password: str, command: str, timeout: int = 300) -> tuple[int, str, str]:
        import paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, username=username, password=password, timeout=30)
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        exit_code = stdout.channel.recv_exit_status()
        out = stdout.read().decode()
        err = stderr.read().decode()
        client.close()
        return exit_code, out, err

    def copy_to_vm(self, ip: str, username: str, password: str, local_path: str, remote_path: str) -> bool:
        import paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, username=username, password=password, timeout=30)
        sftp = client.open_sftp()
        try:
            sftp.put(local_path, remote_path)
            return True
        except Exception as e:
            logger.error(f"SCP put failed: {e}")
            return False
        finally:
            sftp.close()
            client.close()

    def copy_from_vm(self, ip: str, username: str, password: str, remote_path: str, local_path: str) -> bool:
        import paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, username=username, password=password, timeout=30)
        sftp = client.open_sftp()
        try:
            sftp.get(remote_path, local_path)
            return True
        except Exception as e:
            logger.error(f"SCP get failed: {e}")
            return False
        finally:
            sftp.close()
            client.close()


class VMManager:
    def __init__(self, provider: str = "virtualbox"):
        self.provider = self._get_provider(provider)

    def _get_provider(self, provider: str) -> VMProvider:
        if provider == "virtualbox":
            return VirtualBoxProvider()
        raise ValueError(f"Unsupported provider: {provider}")

    def prepare_vm(self, config: VMConfig, use_telemetry_snapshot: bool = False) -> bool:
        snapshot = config.snapshot_telemetry if use_telemetry_snapshot else config.snapshot_clean
        if not self.provider.revert_snapshot(config.name, snapshot):
            return False
        if not self.provider.start_vm(config.name):
            return False
        return self.provider.wait_for_ssh(config.ip, config.username, config.password)

    def run_command(self, config: VMConfig, command: str, timeout: int = 300) -> tuple[int, str, str]:
        return self.provider.execute_remote(config.ip, config.username, config.password, command, timeout)

    def upload_file(self, config: VMConfig, local_path: str, remote_path: str) -> bool:
        return self.provider.copy_to_vm(config.ip, config.username, config.password, local_path, remote_path)

    def download_file(self, config: VMConfig, remote_path: str, local_path: str) -> bool:
        return self.provider.copy_from_vm(config.ip, config.username, config.password, remote_path, local_path)