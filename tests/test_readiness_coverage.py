from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from audit.logger import AuditLevel, AuditLogger
from core.regenerative_loop import Anomaly, AnomalyType, HealingMode, RegenerativeLoop
from sandbox.executor import IsolationLevel, SandboxExecutor


class FakeAudit:
    def __init__(self):
        self.events = []

    def log_event(self, **kwargs):
        self.events.append(kwargs)


class Reloadable:
    def __init__(self, result=True):
        self.result = result
        self.calls = 0

    def reload(self):
        self.calls += 1
        return self.result


def test_regenerative_loop_detects_suggests_and_releases():
    audit = FakeAudit()
    suggested = []
    loop = RegenerativeLoop(
        audit_logger=audit,
        mode=HealingMode.SUGGEST,
        block_rate_threshold=0.6,
        repeated_threshold=3,
        window_size=20,
    )
    loop.on_suggest = suggested.append

    for _ in range(7):
        loop.observe("agent-a", "block", "rule-x")
    for _ in range(3):
        loop.observe("agent-a", "allow")

    actions = loop.tick()
    assert len(actions) == 2
    assert {a.anomaly.type for a in actions} == {
        AnomalyType.HIGH_BLOCK_RATE,
        AnomalyType.REPEATED_VIOLATION,
    }
    assert all(a.action_taken == "suggest" for a in actions)
    assert len(suggested) == 2
    assert audit.events

    assert not loop.is_isolated("agent-a")
    loop.release_agent("agent-a")
    assert loop._violation_count["agent-a"] == 0


def test_regenerative_loop_ask_and_auto_modes():
    anomaly = Anomaly(
        AnomalyType.REPEATED_VIOLATION,
        "repeat",
        0.8,
        agent_id="agent-b",
    )

    ask = RegenerativeLoop(mode=HealingMode.ASK)
    action = ask._heal(anomaly)
    assert action is not None
    assert action.action_taken == "ask"

    isolated = []
    auto = RegenerativeLoop(mode=HealingMode.AUTO)
    auto.on_isolate = isolated.append
    action = auto._heal(anomaly)
    assert action is not None and action.success
    assert auto.is_isolated("agent-b")
    assert isolated == ["agent-b"]
    auto.release_agent("agent-b")
    assert not auto.is_isolated("agent-b")

    unknown = Anomaly(AnomalyType.UNKNOWN, "unknown", 0.1)
    assert auto._heal(unknown) is None


def test_regenerative_loop_policy_reload_success_and_failure():
    anomaly = Anomaly(AnomalyType.POLICY_LOAD_FAILURE, "policy", 0.9)
    engine = Reloadable(True)
    dlp = Reloadable(False)
    loop = RegenerativeLoop(
        permission_engine=engine,
        dlp_gateway=dlp,
        mode=HealingMode.AUTO,
    )
    action = loop._heal(anomaly)
    assert action is not None
    assert action.action_taken == "reload_policies"
    assert action.success is False
    assert engine.calls == 1 and dlp.calls == 1
    assert "permissions_reload=ok" in action.details
    assert "dlp_reload=fail" in action.details


def test_regenerative_loop_small_window_has_no_anomaly():
    loop = RegenerativeLoop(mode=HealingMode.AUTO)
    for _ in range(9):
        loop.observe("agent-small", "block")
    assert loop.tick() == []


def test_sandbox_process_success_and_failure(tmp_path: Path):
    sandbox = SandboxExecutor(level=IsolationLevel.PROCESS, work_dir=tmp_path)
    ok = sandbox.run("printf hello")
    assert ok.success is True
    assert ok.stdout == "hello"
    assert ok.isolation == IsolationLevel.PROCESS

    bad = sandbox.run("sh -c 'exit 3'")
    assert bad.success is False
    assert bad.exit_code == 3
    assert bad.reason == "non_zero_exit"

    none = SandboxExecutor(level=IsolationLevel.NONE, work_dir=tmp_path)
    result = none.run("printf raw")
    assert result.success is True
    assert result.isolation == IsolationLevel.NONE


def test_sandbox_timeout_and_execution_error(tmp_path: Path, monkeypatch):
    sandbox = SandboxExecutor(level=IsolationLevel.PROCESS, work_dir=tmp_path)

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="x", timeout=1)

    monkeypatch.setattr(subprocess, "run", timeout)
    result = sandbox.run("x", timeout=1)
    assert result.reason == "timeout"

    def explode(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(subprocess, "run", explode)
    result = sandbox.run("x")
    assert result.reason == "execution_error"
    assert "boom" in result.stderr


def test_sandbox_docker_command_and_error_paths(tmp_path: Path, monkeypatch):
    calls = []

    def successful(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return SimpleNamespace(returncode=0, stdout="done", stderr="")

    monkeypatch.setattr(subprocess, "run", successful)
    sandbox = SandboxExecutor(
        level=IsolationLevel.DOCKER,
        work_dir=tmp_path,
        network_disabled=True,
        read_only_root=True,
    )
    result = sandbox.run("echo done", timeout=2)
    assert result.success
    command = calls[0][0]
    assert "--network" in command and "none" in command
    assert "--read-only" in command
    assert result.metadata["image"] == "python:3.12-slim"

    def missing(*args, **kwargs):
        raise FileNotFoundError

    monkeypatch.setattr(subprocess, "run", missing)
    result = sandbox.run("echo x")
    assert result.reason == "docker_not_found"

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="docker", timeout=2)

    monkeypatch.setattr(subprocess, "run", timeout)
    result = sandbox.run("echo x", timeout=1)
    assert result.reason == "timeout"

    def explode(*args, **kwargs):
        raise RuntimeError("docker boom")

    monkeypatch.setattr(subprocess, "run", explode)
    result = sandbox.run("echo x")
    assert result.reason == "execution_error"


def test_sandbox_audits_execution(tmp_path: Path):
    audit = FakeAudit()
    sandbox = SandboxExecutor(
        level=IsolationLevel.PROCESS,
        work_dir=tmp_path,
        audit_logger=audit,
    )
    result = sandbox.run("printf ok", actor="tester")
    assert result.success
    event = audit.events[-1]
    assert event["component"] == "sandbox"
    assert event["metadata"]["actor"] == "tester"


def test_audit_logger_writes_jsonl(tmp_path: Path):
    logger = AuditLogger(log_dir=tmp_path, session_id="session-test", also_console=False)
    logger.log_event(
        component="test",
        action="verify",
        decision="success",
        reason="covered",
        level=AuditLevel.SECURITY,
        metadata={"safe": True},
    )
    logger.log_permission("ls", "allow", "safe", rule_id="read-safe", actor="tester")
    logger.log_reload("policy.yml", True, "ok")

    lines = logger.log_file.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3
    assert all("session-test" in line for line in lines)
    assert "verify" in lines[0]
