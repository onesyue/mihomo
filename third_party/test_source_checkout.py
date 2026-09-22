#!/usr/bin/env python3
"""Exercise vendored byte provenance through a real Windows-style Git checkout."""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


class SourceCheckoutTest(unittest.TestCase):
    def checkout(self, directory: Path, *, remove_sing_mux_rule: bool) -> Path:
        source = Path(__file__).resolve().parent
        repo = directory / "repo"
        target = repo / "third_party"
        target.mkdir(parents=True)
        for module in ("quic-go", "sing-mux"):
            shutil.copytree(source / module, target / module)
            for filename in (f"{module}-source.json", f"verify_{module.replace('-', '_')}_source.py"):
                # QUIC's established verifier is named without the -go suffix.
                if filename == "verify_quic_go_source.py":
                    filename = "verify_quic_source.py"
                shutil.copyfile(source / filename, target / filename)
        attributes = (source / ".gitattributes").read_text()
        if remove_sing_mux_rule:
            attributes = "\n".join(line for line in attributes.splitlines() if not line.startswith("sing-mux/")) + "\n"
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

    def verify(self, root: Path, module: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(root / f"verify_{module}_source.py")],
            capture_output=True, text=True,
        )

    def test_windows_checkout_preserves_both_recorded_source_copies(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            checkout = self.checkout(Path(directory), remove_sing_mux_rule=False)
            for module in ("quic", "sing_mux"):
                with self.subTest(module=module):
                    result = self.verify(checkout, module)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_lost_sing_mux_rule_is_detected_by_unchanged_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            checkout = self.checkout(Path(directory), remove_sing_mux_rule=True)
            self.assertEqual(self.verify(checkout, "quic").returncode, 0)
            result = self.verify(checkout, "sing_mux")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("differs from the recorded patched copy", result.stderr)


if __name__ == "__main__":
    unittest.main()
