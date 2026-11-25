#!/usr/bin/env python3
"""Verify sing-mux is the recorded upstream release, unmodified and unreplaced.

The vendored v0.3.10 copy (one-line h2mux Header fix for Go >= 1.27) was
retired once upstream v0.3.12 shipped the same fix. The guarantees move from
a file-set digest to the module graph: every graph requires exactly the
recorded version, no graph replaces it, the go.sum hashes equal the recorded
checksum-database hashes, and no copy is resurrected under third_party/.
"""

import json
from pathlib import Path
import re


def main() -> None:
    directory = Path(__file__).resolve().parent
    root = directory.parent
    record = json.loads((directory / "sing-mux-source.json").read_text())
    if record.get("schema") != 2 or record.get("mode") != "upstream-module":
        raise SystemExit("sing-mux record is not an upstream-module record")
    module, version = record["module"], record["version"]
    if (directory / "sing-mux").exists():
        raise SystemExit("A vendored sing-mux copy exists although the record says upstream-module")
    escaped = re.escape(module)
    for graph in record["module_graphs"]:
        gomod = (root / graph).read_text()
        # Single-line replace or an entry inside a replace ( ... ) block.
        if re.search(rf"^\s*(replace\s+)?{escaped}(\s+v\S+)?\s+=>", gomod, re.MULTILINE):
            raise SystemExit(f"{graph}: {module} must not be replaced")
        required = re.findall(rf"^\s*(?:require\s+)?{escaped}\s+(v\S+)", gomod, re.MULTILINE)
        if required != [version]:
            raise SystemExit(f"{graph}: requires {module} {required}, expected exactly [{version}]")
        gosum = (root / graph).with_name("go.sum").read_text().splitlines()
        entries = {line for line in gosum if line.startswith(f"{module} ")}
        expected = {
            f"{module} {version} {record['go_sum_h1']}",
            f"{module} {version}/go.mod {record['go_mod_h1']}",
        }
        if entries != expected:
            raise SystemExit(f"{graph}: go.sum {module} entries {sorted(entries)} differ from the record")
    print(f"Verified {module} {version} unmodified in {len(record['module_graphs'])} module graphs")


if __name__ == "__main__":
    main()
