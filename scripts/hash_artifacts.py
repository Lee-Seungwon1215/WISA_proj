#!/usr/bin/env python3
"""Create or verify a deterministic SHA-256 manifest for an artifact tree."""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def build_manifest(root: Path, *, exclude: Path | None = None) -> str:
    root = root.resolve()
    if not root.is_dir():
        raise ValueError(f"artifact root is not a directory: {root}")
    excluded = exclude.resolve() if exclude is not None else None
    rows: list[str] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if path.is_symlink():
            raise ValueError(f"artifact tree contains a symlink: {path.relative_to(root)}")
        if not path.is_file() or (excluded is not None and path.resolve() == excluded):
            continue
        relative = path.relative_to(root).as_posix()
        if "\n" in relative or "\r" in relative:
            raise ValueError("artifact filename contains a newline")
        rows.append(f"{sha256(path)}  {relative}")
    if not rows:
        raise ValueError("artifact tree contains no files")
    return "\n".join(rows) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--write", type=Path, metavar="MANIFEST")
    action.add_argument("--check", type=Path, metavar="MANIFEST")
    args = parser.parse_args()
    manifest_path = (args.write or args.check).resolve()
    try:
        content = build_manifest(args.root, exclude=manifest_path)
    except (OSError, ValueError) as exc:
        print(f"[artifact-hash] ERROR: {exc}", file=sys.stderr)
        return 2
    if args.write is not None:
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(content, encoding="utf-8")
        print(f"[artifact-hash] wrote {manifest_path}")
        return 0
    try:
        actual = manifest_path.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"[artifact-hash] ERROR: {exc}", file=sys.stderr)
        return 2
    if actual != content:
        print("[artifact-hash] ERROR: manifest mismatch", file=sys.stderr)
        return 2
    print(f"[artifact-hash] OK: {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
