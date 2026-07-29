#!/usr/bin/env python3
"""Validate every committed example config and forbid implicit shell steps."""

from __future__ import annotations

import sys
from pathlib import Path

import yaml
from pydantic import ValidationError

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ctkat.config import load_config  # noqa: E402


def main() -> int:
    errors: list[str] = []
    configs = sorted((ROOT / "examples").glob("**/ctkat*.yaml"))
    for config_path in configs:
        relative = config_path.relative_to(ROOT)
        try:
            raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
            cfg = load_config(config_path)
        except (OSError, ValueError, ValidationError, yaml.YAMLError) as exc:
            errors.append(f"{relative}: does not load: {exc}")
            continue
        for section in ("build", "kat"):
            data = raw.get(section) if isinstance(raw, dict) else None
            if isinstance(data, dict) and data.get("command") is not None:
                errors.append(f"{relative}: {section}.command is forbidden in examples")
        if cfg.build.argv is None:
            errors.append(f"{relative}: build must use argv")
        if cfg.kat is not None and cfg.kat.argv is None:
            errors.append(f"{relative}: kat must use argv")

    if not configs:
        errors.append("no example configs discovered")
    if errors:
        for error in errors:
            print(f"[example-configs] ERROR: {error}", file=sys.stderr)
        return 1
    print(f"[example-configs] OK: {len(configs)} shell-free configs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
