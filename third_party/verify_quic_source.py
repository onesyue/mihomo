#!/usr/bin/env python3
"""Verify the exported, signed MetaCubeX-compatible QUIC source copy."""

import hashlib
import json
from pathlib import Path


def main() -> None:
    directory = Path(__file__).resolve().parent
    record = json.loads((directory / "quic-go-source.json").read_text())
    root = directory / "quic-go"
    paths = list(root.rglob("*"))
    if any(path.is_symlink() for path in paths):
        raise SystemExit("Unexpected symlink in vendored QUIC source")
    files = sorted(
        (path for path in paths if path.is_file()),
        key=lambda path: path.relative_to(root).as_posix(),
    )
    digest = hashlib.sha256()
    for path in files:
        checksum = hashlib.sha256(path.read_bytes()).hexdigest()
        relative = path.relative_to(root).as_posix()
        digest.update(f"{checksum}  {relative}\n".encode())
    if len(files) != record["file_count"] or digest.hexdigest() != record["file_set_sha256"]:
        raise SystemExit("Vendored QUIC source differs from the signed export")
    if not (root / "LICENSE").is_file():
        raise SystemExit("Vendored QUIC license is missing")
    print(f"Verified {len(files)} QUIC source files from {record['maintenance_tag']}")


if __name__ == "__main__":
    main()
