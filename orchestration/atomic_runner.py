import json
import logging
import subprocess
from pathlib import Path
from dataclasses import dataclass
from typing import Optional
from orchestration.vm_manager import VMManager, VMConfig

logger = logging.getLogger(__name__)


@dataclass
class AtomicTest:
    technique_id: str
    test_name: str
    test_guid: str
    description: str
    executor: str
    command: str
    cleanup_command: Optional[str] = None
    dependencies: list = None
    input_arguments: dict = None


@dataclass
class ExecutionResult:
    technique_id: str
    test_guid: str
    success: bool
    stdout: str
    stderr: str
    exit_code: int
    execution_time: float
    telemetry_collected: bool = False


class AtomicRunner:
    def __init__(self, atomic_repo_path: str, vm_manager: VMManager):
        self.atomic_repo_path = Path(atomic_repo_path)
        self.vm_manager = vm_manager

    def load_technique_tests(self, technique_id: str) -> list[AtomicTest]:
        technique_path = self.atomic_repo_path / "atomics" / technique_id / f"{technique_id}.yaml"
        if not technique_path.exists():
            logger.warning(f"Technique file not found: {technique_path}")
            return []

        import yaml
        with open(technique_path) as f:
            data = yaml.safe_load(f)

        tests = []
        for test in data.get("atomic_tests", []):
            tests.append(AtomicTest(
                technique_id=technique_id,
                test_name=test.get("name", ""),
                test_guid=test.get("auto_generated_guid", ""),
                description=test.get("description", ""),
                executor=test.get("executor", {}).get("name", ""),
                command=test.get("executor", {}).get("command", ""),
                cleanup_command=test.get("executor", {}).get("cleanup_command"),
                dependencies=test.get("dependencies", []),
                input_arguments=test.get("input_arguments", {})
            ))
        return tests

    def resolve_dependencies(self, config: VMConfig, test: AtomicTest) -> bool:
        if not test.dependencies:
            return True

        for dep in test.dependencies:
            if "command" in dep:
                exit_code, _, _ = self.vm_manager.run_command(config, dep["command"])
                if exit_code != 0:
                    logger.warning(f"Dependency check failed: {dep['command']}")
                    return False
            if "get_prereq_command" in dep:
                exit_code, _, _ = self.vm_manager.run_command(config, dep["get_prereq_command"])
                if exit_code != 0:
                    logger.warning(f"Prereq install failed: {dep['get_prereq_command']}")
                    return False
        return True

    def execute_test(self, config: VMConfig, test: AtomicTest, extra_args: dict = None) -> ExecutionResult:
        import time
        start = time.time()

        if not self.resolve_dependencies(config, test):
            return ExecutionResult(
                technique_id=test.technique_id,
                test_guid=test.test_guid,
                success=False,
                stdout="",
                stderr="Dependencies not satisfied",
                exit_code=-1,
                execution_time=0
            )

        command = self._render_command(test.command, test.input_arguments, extra_args or {})
        logger.info(f"Executing {test.technique_id} - {test.test_name}: {command[:100]}...")

        exit_code, stdout, stderr = self.vm_manager.run_command(config, command)

        if test.cleanup_command:
            cleanup_cmd = self._render_command(test.cleanup_command, test.input_arguments, extra_args or {})
            self.vm_manager.run_command(config, cleanup_cmd)

        execution_time = time.time() - start
        success = exit_code == 0

        return ExecutionResult(
            technique_id=test.technique_id,
            test_guid=test.test_guid,
            success=success,
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            execution_time=execution_time
        )

    def _render_command(self, command: str, input_args: dict, extra_args: dict) -> str:
        all_args = {**(input_args or {}), **extra_args}
        for key, value in all_args.items():
            placeholder = f"#{key}#"
            command = command.replace(placeholder, str(value))
        return command

    def run_technique(self, config: VMConfig, technique_id: str, extra_args: dict = None) -> list[ExecutionResult]:
        tests = self.load_technique_tests(technique_id)
        results = []
        for test in tests:
            result = self.execute_test(config, test, extra_args)
            results.append(result)
            logger.info(f"Test {test.test_guid} {'PASSED' if result.success else 'FAILED'} ({result.execution_time:.1f}s)")
        return results