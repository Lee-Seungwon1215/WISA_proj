#!/usr/bin/env python3
"""Validate vendored-source inventory, integrity hashes, and notices."""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INVENTORY = ROOT / "third_party.toml"
NOTICES = ROOT / "THIRD_PARTY_NOTICES.md"
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def tree_sha256(path: Path) -> str:
    """Hash sorted relative paths and file bytes for one vendored tree."""

    digest = hashlib.sha256()
    files = sorted(p for p in path.rglob("*") if p.is_file())
    if not files:
        raise ValueError(f"{path}: no files found")
    for file_path in files:
        if file_path.is_symlink():
            raise ValueError(f"{file_path}: symlinks are not allowed in vendored trees")
        relative = file_path.relative_to(path).as_posix().encode("utf-8")
        digest.update(relative)
        digest.update(b"\0")
        digest.update(file_path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def load_entries(path: Path = INVENTORY) -> list[dict[str, str]]:
    with path.open("rb") as handle:
        data = tomllib.load(handle)
    entries = data.get("package", [])
    if not isinstance(entries, list) or not entries:
        raise ValueError("third_party.toml must contain one or more [[package]] entries")
    return entries


def discovered_vendor_dirs() -> set[str]:
    found = set()
    for candidate in (ROOT / "examples").glob("pqc_*/*"):
        marker = candidate.parent / ".ctkat-vendor"
        declared = set()
        if marker.is_file():
            declared = {
                line.strip()
                for line in marker.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            }
        if candidate.is_dir() and (
            candidate.name == "common"
            or candidate.name.startswith("clean")
            or candidate.name in declared
        ):
            found.add(candidate.relative_to(ROOT).as_posix())
    vendor_root = ROOT / "ctkat" / "_vendor"
    if vendor_root.is_dir():
        for candidate in vendor_root.iterdir():
            if candidate.is_dir() and any(path.is_file() for path in candidate.rglob("*")):
                found.add(candidate.relative_to(ROOT).as_posix())
    return found


def render_notices(entries: list[dict[str, str]]) -> str:
    lines = [
        "# Third-party notices",
        "",
        "CT-KAT's MIT license does not relicense the material listed below.",
        "Integrity hashes cover sorted relative paths and file bytes using",
        "`scripts/check_third_party.py::tree_sha256`.",
        "",
        "This file is generated from `third_party.toml`. Regenerate it with:",
        "",
        "```bash",
        "python scripts/check_third_party.py --write-notices",
        "```",
        "",
    ]
    for entry in entries:
        if entry.get("revision"):
            identity_line = f"- Revision: `{entry['revision']}`"
        else:
            identity_line = f"- Artifact SHA-256: `{entry['artifact_sha256']}`"
        lines.extend(
            [
                f"## {entry['name']}",
                "",
                f"- Local path: `{entry['local_path']}`",
                f"- Upstream: {entry['upstream_url']}",
                identity_line,
                f"- Upstream path: `{entry['upstream_path']}`",
                f"- License: `{entry['license']}`",
                f"- License file: `{entry['license_file']}`",
                f"- Tree SHA-256: `{entry['tree_sha256']}`",
                f"- Local modifications: {entry['modifications']}",
                f"- Detailed provenance: `{entry['provenance_file']}`",
                "",
            ]
        )
    return "\n".join(lines)


def validate(entries: list[dict[str, str]]) -> list[str]:
    errors: list[str] = []
    required = {
        "name",
        "local_path",
        "upstream_url",
        "upstream_path",
        "license",
        "license_file",
        "tree_sha256",
        "modifications",
        "provenance_file",
    }
    seen_paths: set[str] = set()
    for index, entry in enumerate(entries):
        label = entry.get("name", f"entry {index}")
        missing = required.difference(entry)
        if missing:
            errors.append(f"{label}: missing fields {sorted(missing)}")
            continue
        revision = entry.get("revision", "")
        artifact_sha256 = entry.get("artifact_sha256", "")
        if bool(revision) == bool(artifact_sha256):
            errors.append(f"{label}: set exactly one of revision or artifact_sha256")
            continue
        local_path = entry["local_path"]
        if local_path in seen_paths:
            errors.append(f"{label}: duplicate local_path {local_path}")
        seen_paths.add(local_path)
        if revision and not REVISION_RE.fullmatch(revision):
            errors.append(f"{label}: revision must be a full 40-hex commit")
        if artifact_sha256 and not SHA256_RE.fullmatch(artifact_sha256):
            errors.append(f"{label}: artifact_sha256 must be 64 lowercase hex characters")
        if not SHA256_RE.fullmatch(entry["tree_sha256"]):
            errors.append(f"{label}: tree_sha256 must be 64 lowercase hex characters")
        if not entry["upstream_url"].startswith("https://"):
            errors.append(f"{label}: upstream_url must use https")
        if not entry["upstream_path"].strip() or not entry["modifications"].strip():
            errors.append(f"{label}: upstream_path/modifications must be explicit")

        vendor_dir = ROOT / local_path
        if not vendor_dir.is_dir():
            errors.append(f"{label}: missing vendored directory {local_path}")
        else:
            actual_hash = tree_sha256(vendor_dir)
            if actual_hash != entry["tree_sha256"]:
                errors.append(
                    f"{label}: tree hash drift: inventory={entry['tree_sha256']} "
                    f"actual={actual_hash}"
                )

        license_path = ROOT / entry["license_file"]
        if not license_path.is_file():
            errors.append(f"{label}: missing license file {entry['license_file']}")
        provenance_path = ROOT / entry["provenance_file"]
        if not provenance_path.is_file():
            errors.append(f"{label}: missing provenance file {entry['provenance_file']}")
        else:
            provenance = provenance_path.read_text(encoding="utf-8")
            for expected in (
                entry["local_path"],
                revision or artifact_sha256,
                entry["tree_sha256"],
            ):
                if expected not in provenance:
                    errors.append(
                        f"{label}: {entry['provenance_file']} does not contain {expected}"
                    )

    discovered = discovered_vendor_dirs()
    if seen_paths != discovered:
        for missing in sorted(discovered - seen_paths):
            errors.append(f"untracked vendored directory: {missing}")
        for stale in sorted(seen_paths - discovered):
            errors.append(f"inventory path is not a discovered vendored directory: {stale}")

    for fetch_info in (ROOT / "examples").glob("pqc_*/FETCH_INFO.md"):
        text = fetch_info.read_text(encoding="utf-8")
        if re.search(r"(?:@\s*master|of master|Revision:\s*`?master)", text, re.I):
            errors.append(
                f"{fetch_info.relative_to(ROOT)}: floating master provenance is forbidden"
            )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--write-notices",
        action="store_true",
        help="rewrite THIRD_PARTY_NOTICES.md after validation",
    )
    args = parser.parse_args()

    try:
        entries = load_entries()
        errors = validate(entries)
    except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
        print(f"[third-party] ERROR: {exc}", file=sys.stderr)
        return 1
    if errors:
        for error in errors:
            print(f"[third-party] ERROR: {error}", file=sys.stderr)
        return 1

    expected_notices = render_notices(entries)
    if args.write_notices:
        NOTICES.write_text(expected_notices, encoding="utf-8")
        print(f"[third-party] wrote {NOTICES}")
        return 0
    if not NOTICES.is_file() or NOTICES.read_text(encoding="utf-8") != expected_notices:
        print(
            "[third-party] ERROR: THIRD_PARTY_NOTICES.md is stale; run "
            "python scripts/check_third_party.py --write-notices",
            file=sys.stderr,
        )
        return 1
    print(f"[third-party] OK: {len(entries)} vendored trees")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
