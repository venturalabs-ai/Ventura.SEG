"""
Ventura.SEG — Sandbox de Execução
=================================
Isola a execução de comandos em ambiente restrito.

Níveis de isolamento suportados:
- none     : sem isolamento (apenas para testes)
- process  : subprocess com limites básicos, sem shell
- docker   : container Docker hardenizado (recomendado)

Princípio: Isolamento real, não apenas checagem em software.
"""

from __future__ import annotations

import shlex
import subprocess  # nosec B404 - subprocess is the explicit execution primitive of this sandbox
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

try:
    from audit.logger import AuditLogger
except ImportError:
    AuditLogger = None  # type: ignore


class IsolationLevel(str, Enum):
    NONE = "none"
    PROCESS = "process"
    DOCKER = "docker"


@dataclass(frozen=True)
class ExecutionResult:
    success: bool
    exit_code: int
    stdout: str
    stderr: str
    isolation: IsolationLevel
    reason: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


class SandboxExecutor:
    """Executor com isolamento configurável."""

    def __init__(
        self,
        level: IsolationLevel = IsolationLevel.PROCESS,
        docker_image: str = "python:3.12-slim",
        work_dir: str | Path | None = None,
        network_disabled: bool = True,
        read_only_root: bool = True,
        memory_limit: str = "256m",
        cpu_limit: str = "0.5",
        audit_logger: Any = None,
    ) -> None:
        self.level = level
        self.docker_image = docker_image
        self.work_dir = Path(work_dir) if work_dir else Path(tempfile.gettempdir()) / "ventura-sandbox"
        self.network_disabled = network_disabled
        self.read_only_root = read_only_root
        self.memory_limit = memory_limit
        self.cpu_limit = cpu_limit
        self.audit = audit_logger
        self.work_dir.mkdir(parents=True, exist_ok=True)

    def run(self, command: str, timeout: int = 30, actor: str = "agent") -> ExecutionResult:
        if self.level == IsolationLevel.NONE:
            result = self._run_process(command, timeout, isolated=False)
        elif self.level == IsolationLevel.PROCESS:
            result = self._run_process(command, timeout, isolated=True)
        elif self.level == IsolationLevel.DOCKER:
            result = self._run_docker(command, timeout)
        else:
            result = ExecutionResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr=f"Nível de isolamento desconhecido: {self.level}",
                isolation=self.level,
                reason="invalid_isolation_level",
            )
        self._audit(command, result, actor)
        return result

    def _run_process(self, command: str, timeout: int, isolated: bool) -> ExecutionResult:
        """Executa diretamente argv sem invocar shell, evitando expansão/injection de shell."""
        try:
            argv = shlex.split(command)
            if not argv:
                return ExecutionResult(
                    success=False,
                    exit_code=-1,
                    stdout="",
                    stderr="Comando vazio",
                    isolation=IsolationLevel.PROCESS if isolated else IsolationLevel.NONE,
                    reason="empty_command",
                )
            completed = subprocess.run(  # nosec B603 - argv is parsed without shell; permission policy gates commands upstream
                argv,
                shell=False,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=str(self.work_dir) if isolated else None,
            )
            return ExecutionResult(
                success=completed.returncode == 0,
                exit_code=completed.returncode,
                stdout=completed.stdout,
                stderr=completed.stderr,
                isolation=IsolationLevel.PROCESS if isolated else IsolationLevel.NONE,
                reason="ok" if completed.returncode == 0 else "non_zero_exit",
            )
        except (ValueError, subprocess.TimeoutExpired) as exc:
            if isinstance(exc, subprocess.TimeoutExpired):
                reason = "timeout"
                stderr = f"Timeout após {timeout}s"
            else:
                reason = "invalid_command"
                stderr = str(exc)
            return ExecutionResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr=stderr,
                isolation=IsolationLevel.PROCESS if isolated else IsolationLevel.NONE,
                reason=reason,
            )
        except Exception as exc:
            return ExecutionResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr=str(exc),
                isolation=IsolationLevel.PROCESS if isolated else IsolationLevel.NONE,
                reason="execution_error",
            )

    def _run_docker(self, command: str, timeout: int) -> ExecutionResult:
        """Executa em Docker com rede opcionalmente desabilitada e rootfs somente leitura."""
        docker_cmd = [
            "docker", "run", "--rm",
            f"--memory={self.memory_limit}",
            f"--cpus={self.cpu_limit}",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges:true",
        ]
        if self.network_disabled:
            docker_cmd.extend(["--network", "none"])
        if self.read_only_root:
            docker_cmd.append("--read-only")
            docker_cmd.extend(["--tmpfs", "/tmp:rw,noexec,nosuid,size=64m"])  # nosec B108 - container-internal tmpfs mount, not host temp-file creation
        docker_cmd.extend([self.docker_image, "sh", "-c", command])

        try:
            completed = subprocess.run(  # nosec B603 - executable argv is fixed to docker; command is confined inside configured container
                docker_cmd,
                shell=False,
                capture_output=True,
                text=True,
                timeout=timeout + 5,
            )
            return ExecutionResult(
                success=completed.returncode == 0,
                exit_code=completed.returncode,
                stdout=completed.stdout,
                stderr=completed.stderr,
                isolation=IsolationLevel.DOCKER,
                reason="ok" if completed.returncode == 0 else "non_zero_exit",
                metadata={"image": self.docker_image},
            )
        except FileNotFoundError:
            return ExecutionResult(False, -1, "", "Docker não encontrado no PATH", IsolationLevel.DOCKER, "docker_not_found")
        except subprocess.TimeoutExpired:
            return ExecutionResult(False, -1, "", f"Timeout após {timeout}s (Docker)", IsolationLevel.DOCKER, "timeout")
        except Exception as exc:
            return ExecutionResult(False, -1, "", str(exc), IsolationLevel.DOCKER, "execution_error")

    def _audit(self, command: str, result: ExecutionResult, actor: str) -> None:
        if self.audit is None:
            return
        self.audit.log_event(
            component="sandbox",
            action="execute",
            decision="success" if result.success else "failed",
            reason=result.reason,
            metadata={
                "actor": actor,
                "isolation": result.isolation.value,
                "exit_code": result.exit_code,
                "command_preview": command[:80],
            },
        )
