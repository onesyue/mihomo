#!/usr/bin/env python3
"""Verify the vendored sing-mux copy is exactly upstream v0.3.10 + the recorded patch."""

import hashlib
import json
from pathlib import Path


def file_set_digest(root: Path) -> tuple[int, str]:
    paths = list(root.rglob("*"))
    if any(path.is_symlink() for path in paths):
        raise SystemExit("Unexpected symlink in vendored sing-mux source")
    files = sorted(
        (p for p in paths if p.is_file()),
        key=lambda p: p.relative_to(root).as_posix(),
    )
    digest = hashlib.sha256()
    for path in files:
        checksum = hashlib.sha256(path.read_bytes()).hexdigest()
        digest.update(f"{checksum}  {path.relative_to(root).as_posix()}\n".encode())
    return len(files), digest.hexdigest()


def main() -> None:
    directory = Path(__file__).resolve().parent
    record = json.loads((directory / "sing-mux-source.json").read_text())
    root = directory / "sing-mux"
    count, digest = file_set_digest(root)
    if count != record["file_count"] or digest != record["file_set_sha256"]:
        raise SystemExit("Vendored sing-mux differs from the recorded patched copy")
    if not (root / "LICENSE").is_file():
        raise SystemExit("Vendored sing-mux license is missing")
    h2mux = (root / "h2mux.go").read_text()
    if "Header: make(http.Header)," not in h2mux:
        raise SystemExit("h2mux CONNECT request lost its non-nil Header")
    print(f"Verified {count} sing-mux files ({record['upstream_version']} + patch)")


if __name__ == "__main__":
    main()
