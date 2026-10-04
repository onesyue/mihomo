#!/usr/bin/env python3
"""Exercise vendored byte provenance through a real Windows-style Git checkout.

sing-mux is consumed from the Go checksum database since v0.3.12 (see
sing-mux-source.json); QUIC is the remaining byte-for-byte vendored copy.
"""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


class SourceCheckoutTest(unittest.TestCase):
    def checkout(self, directory: Path, *, remove_quic_rule: bool) -> Path:
        source = Path(__file__).resolve().parent
        repo = directory / "repo"
        target = repo / "third_party"
        target.mkdir(parents=True)
        shutil.copytree(source / "quic-go", target / "quic-go")
        for filename in ("quic-go-source.json", "verify_quic_source.py"):
            shutil.copyfile(source / filename, target / filename)
        attributes = (source / ".gitattributes").read_text()
        if remove_quic_rule:
            attributes = "\n".join(line for line in attributes.splitlines() if not line.startswith("quic-go/")) + "\n"
        (target / ".gitattributes").write_text(attributes)
        environment = os.environ.copy()
        for key in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"):
            environment.pop(key, None)

        def git(*args: str) -> None:
            subprocess.run(
                ["git", "-c", "core.autocrlf=true", *args],
                cwd=repo, env=environment, check=True, capture_output=True,
            )

        git("init", "-q")
        git("add", "-f", "third_party")
        output = directory / "checkout"
        output.mkdir()
        git("checkout-index", "--all", f"--prefix={output.as_posix()}/")
        return output / "third_party"

    def verify(self, root: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(root / "verify_quic_source.py")],
            capture_output=True, text=True,
        )

    def test_windows_checkout_preserves_the_recorded_quic_copy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            checkout = self.checkout(Path(directory), remove_quic_rule=False)
            result = self.verify(checkout)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_lost_quic_rule_is_detected_by_unchanged_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            checkout = self.checkout(Path(directory), remove_quic_rule=True)
            result = self.verify(checkout)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("differs from the signed export", result.stderr)


if __name__ == "__main__":
    unittest.main()
