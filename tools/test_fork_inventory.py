"""Offline Git fixtures; never access remotes or devices."""

import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import fork_inventory as tool


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name)
        self.git("init", "-b", "fork")
        self.git("config", "user.email", "fixture@example.invalid")
        self.git("config", "user.name", "Offline fixture")
        self.base = self.commit("base", "base", "base")
        self.git("branch", "upstream")

    def git(self, *args):
        env = {
            **os.environ,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
        }
        return subprocess.check_output(
            ["git", "-C", str(self.repo), "-c", "commit.gpgsign=false", *args],
            env=env,
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()

    def commit(self, filename, content, subject):
        (self.repo / filename).write_text(content)
        self.git("add", filename)
        self.git("commit", "-m", subject)
        return self.git("rev-parse", "HEAD")

    def report(self):
        return tool.inventory(self.repo, "fork", "upstream")

    def test_exact_ancestry_has_no_false_gap(self):
        self.assertEqual(self.report()["upstream_review_required"], [])
        self.assertEqual(self.report()["fork_patch_stack"], [])

    def test_live_tag_commit_identity_must_match(self):
        with self.assertRaisesRegex(tool.InventoryError, "does not match"):
            tool.inventory(self.repo, "fork", "upstream", {"sha": "0" * 40})

    def test_cherry_pick_own_patch_and_missing_fix(self):
        own = self.commit("local", "local", "retain mobile stack")
        self.git("checkout", "upstream")
        equivalent = self.commit("upstream", "one", "fix: cached byte order")
        missing = self.commit("missing", "two", "fix: close resource")
        feature = self.commit("feature", "three", "add optional feature")
        self.git("checkout", "fork")
        self.git("cherry-pick", equivalent)
        applied = self.git("rev-parse", "HEAD")
        self.assertNotEqual(applied, equivalent)
        report = self.report()
        self.assertEqual(
            [r["sha"] for r in report["upstream_patch_equivalent"]], [equivalent]
        )
        self.assertEqual(
            [r["sha"] for r in report["fork_equivalent_backports"]], [applied]
        )
        self.assertEqual([r["sha"] for r in report["fork_patch_stack"]], [own])
        self.assertEqual(
            [r["sha"] for r in report["upstream_review_required"]], [missing, feature]
        )
        self.assertEqual(
            [r["fix_subject_hint"] for r in report["upstream_review_required"]],
            [True, False],
        )

    def test_adapted_backport_is_unknown_not_definitely_missing(self):
        self.commit("fix", "fixed\nlocal adaptation\n", "adapt fix")
        self.git("checkout", "upstream")
        self.commit("fix", "fixed\n", "fix: behavior")
        row = self.report()["upstream_review_required"][0]
        self.assertEqual(row["status"], "review_required")
        self.assertIn("adapted backports", self.report()["limitations"][0])

    def test_squash_is_unknown(self):
        self.git("checkout", "upstream")
        self.commit("one", "1", "fix one")
        self.commit("two", "2", "fix two")
        self.git("checkout", "fork")
        self.git("merge", "--squash", "upstream")
        self.git("commit", "-m", "combined backport")
        self.assertEqual(len(self.report()["upstream_review_required"]), 2)

    def test_merges_are_separate(self):
        self.git("checkout", "-b", "topic")
        self.commit("topic", "topic", "topic change")
        self.git("checkout", "fork")
        self.git("merge", "--no-ff", "topic", "-m", "integrate topic")
        report = self.report()
        self.assertEqual(len(report["merges"]["fork"]), 1)
        self.assertEqual(len(report["fork_patch_stack"]), 1)

    def test_missing_and_option_like_refs_fail(self):
        for ref in ("missing", "--help"):
            with self.assertRaises(tool.InventoryError):
                tool.inventory(self.repo, "fork", ref)

    def test_unrelated_history_fails(self):
        self.git("checkout", "--orphan", "unrelated")
        self.git("rm", "-rf", ".")
        self.commit("other", "other", "unrelated")
        with self.assertRaises(tool.InventoryError):
            tool.inventory(self.repo, "fork", "unrelated")

    def test_shallow_history_fails(self):
        shallow = self.repo / "shallow"
        self.git("clone", "--depth", "1", self.repo.as_uri(), str(shallow))
        with self.assertRaisesRegex(tool.InventoryError, "shallow"):
            tool.inventory(shallow, "HEAD", "HEAD")

    def test_offline_output_is_deterministic_and_does_not_mutate(self):
        before = self.git("show-ref"), self.git("status", "--porcelain")
        outputs = []
        with patch.object(
            tool, "latest_release", side_effect=AssertionError("network forbidden")
        ):
            for _ in range(2):
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    self.assertEqual(
                        tool.main(
                            ["--repo", str(self.repo), "--upstream-ref", "upstream"]
                        ),
                        0,
                    )
                outputs.append(out.getvalue())
        self.assertEqual(outputs[0], outputs[1])
        self.assertEqual(json.loads(outputs[0])["selection"], "explicit_offline_ref")
        self.assertEqual(
            before, (self.git("show-ref"), self.git("status", "--porcelain"))
        )


class ReleaseTests(unittest.TestCase):
    def test_live_latest_stable_metadata(self):
        release = {
            "tag_name": "v1.2.3",
            "draft": False,
            "prerelease": False,
            "published_at": "date",
        }
        with patch.object(
            tool.urllib.request,
            "urlopen",
            side_effect=[
                io.BytesIO(json.dumps(release).encode()),
                io.BytesIO(json.dumps({"sha": "a" * 40}).encode()),
            ],
        ) as fetch:
            self.assertEqual(
                tool.latest_release(),
                {"tag": "v1.2.3", "sha": "a" * 40, "published_at": "date"},
            )
        self.assertEqual(fetch.call_args_list[0].args[0].full_url, tool.LATEST_URL)
        self.assertTrue(
            fetch.call_args_list[1].args[0].full_url.endswith("/commits/v1.2.3")
        )

    def test_invalid_latest_does_not_fall_back(self):
        for response in (
            [],
            {},
            {"tag_name": "Alpha", "draft": False, "prerelease": True},
        ):
            with (
                patch.object(
                    tool.urllib.request,
                    "urlopen",
                    return_value=io.BytesIO(json.dumps(response).encode()),
                ),
                self.assertRaises(tool.InventoryError),
            ):
                tool.latest_release()

    def test_network_failure_is_nonzero_without_report(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            patch.object(
                tool.urllib.request, "urlopen", side_effect=OSError("offline")
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            self.assertEqual(tool.main([]), 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("no cached fallback", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
