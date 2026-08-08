"""Health check do control-plane Ventura.SEG."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

_STARTED = time.time()
_ROOT = Path(__file__).resolve().parents[2]


def check() -> dict[str, Any]:
    policies = _ROOT / "policies"
    required = [
        policies / "allowlist_commands.yaml",
        policies / "allowlist_domains.yaml",
        policies / "dlp_rules.yaml",
    ]
    missing = [str(p.name) for p in required if not p.is_file()]
    status = "ok" if not missing else "degraded"
    return {
        "status": status,
        "service": "ventura-seg",
        "uptime_sec": round(time.time() - _STARTED, 2),
        "version": (_ROOT / "VERSION").read_text(encoding="utf-8").strip()
        if (_ROOT / "VERSION").is_file()
        else "unknown",
        "missing_policies": missing,
    }


def assert_healthy() -> None:
    result = check()
    if result["status"] != "ok":
        raise RuntimeError(f"unhealthy: {result}")
