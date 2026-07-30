#!/usr/bin/env python3
"""Inspect built wheel/sdist contents and core metadata without installing."""

from __future__ import annotations

import argparse
import email
import sys
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ctkat import __version__  # noqa: E402

VERSION = __version__
TEMPLATES = {
    "harness_generic.c.j2",
    "harness_kem.c.j2",
    "harness_sign.c.j2",
    "timing_generic.c.j2",
    "timing_kem.c.j2",
    "timing_sign.c.j2",
}


def _wheel_checks(path: Path) -> list[str]:
    errors: list[str] = []
    with zipfile.ZipFile(path) as archive:
        names = set(archive.namelist())
        expected = {f"ctkat/templates/{name}" for name in TEMPLATES}
        expected.add("ctkat/py.typed")
        expected.add("ctkat/schemas/evidence-v2.schema.json")
        missing = expected - names
        if missing:
            errors.append(f"{path.name}: missing wheel resources {sorted(missing)}")
        if any(name.startswith(("examples/", "tests/", "scripts/")) for name in names):
            errors.append(f"{path.name}: development trees leaked into wheel")
        metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
        if len(metadata_names) != 1:
            errors.append(f"{path.name}: expected one METADATA, got {metadata_names}")
        else:
            metadata = email.message_from_bytes(archive.read(metadata_names[0]))
            if metadata.get("Version") != VERSION:
                errors.append(
                    f"{path.name}: metadata version={metadata.get('Version')!r}, "
                    f"expected={VERSION!r}"
                )
            if metadata.get("License-Expression") != "MIT":
                errors.append(
                    f"{path.name}: License-Expression must be MIT, got "
                    f"{metadata.get('License-Expression')!r}"
                )
            if metadata.get("Requires-Python") != ">=3.11":
                errors.append(
                    f"{path.name}: Requires-Python drift: {metadata.get('Requires-Python')!r}"
                )
    return errors


def _sdist_checks(path: Path) -> list[str]:
    errors: list[str] = []
    with tarfile.open(path, "r:gz") as archive:
        names = archive.getnames()
        stripped = {name.split("/", 1)[1] for name in names if "/" in name}
        expected = {f"ctkat/templates/{name}" for name in TEMPLATES}
        expected.update(
            {
                "README.md",
                "LICENSE",
                "pyproject.toml",
                "ctkat/py.typed",
                "ctkat/schemas/evidence-v2.schema.json",
                "CHANGELOG.md",
                "SECURITY.md",
                "THIRD_PARTY_NOTICES.md",
            }
        )
        missing = expected - stripped
        if missing:
            errors.append(f"{path.name}: missing sdist resources {sorted(missing)}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dist_dir", type=Path)
    args = parser.parse_args()
    wheels = sorted(args.dist_dir.glob("ctkat-*.whl"))
    sdists = sorted(args.dist_dir.glob("ctkat-*.tar.gz"))
    errors: list[str] = []
    if len(wheels) != 1:
        errors.append(f"expected one wheel in {args.dist_dir}, got {len(wheels)}")
    if len(sdists) != 1:
        errors.append(f"expected one sdist in {args.dist_dir}, got {len(sdists)}")
    for wheel in wheels:
        errors.extend(_wheel_checks(wheel))
    for sdist in sdists:
        errors.extend(_sdist_checks(sdist))
    if errors:
        for error in errors:
            print(f"[distribution] ERROR: {error}", file=sys.stderr)
        return 1
    print(f"[distribution] OK: {wheels[0].name}, {sdists[0].name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
