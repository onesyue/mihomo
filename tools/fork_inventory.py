"""Read-only upstream/fork triage. Patch inequality is not proof of a missing fix."""

import argparse
import json
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

LATEST_URL = "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest"
STABLE_TAG = re.compile(r"v\d+\.\d+\.\d+")
FIX_HINT = re.compile(
    r"\b(fix(?:es|ed)?|bug|panic|race|deadlock|CVE|regression)\b", re.IGNORECASE
)


class InventoryError(Exception):
    """Inputs cannot support a complete inventory."""


def git(repo: Path, *args: str) -> str:
    try:
        result = subprocess.run(
            ["git", "--no-pager", "-C", str(repo), *args],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise InventoryError("git is unavailable or timed out") from exc
    if result.returncode:
        # Do not echo Git stderr: a repository's configuration can contain credentials.
        raise InventoryError(
            f"git {args[0]} failed; check refs and complete local history"
        )
    return result.stdout.strip()


def public_json(url: str):
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "mihomo-fork-inventory",
            "Cache-Control": "no-cache",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return json.load(response)
    except (OSError, ValueError, urllib.error.URLError) as exc:
        raise InventoryError(
            "latest stable release lookup failed; no cached fallback was used"
        ) from exc


def latest_release() -> dict:
    release = public_json(LATEST_URL)
    if (
        not isinstance(release, dict)
        or release.get("draft") is not False
        or release.get("prerelease") is not False
        or not isinstance(release.get("tag_name"), str)
        or not STABLE_TAG.fullmatch(release["tag_name"])
    ):
        raise InventoryError(
            "latest release response does not identify a stable version"
        )
    commit = public_json(
        "https://api.github.com/repos/MetaCubeX/mihomo/commits/" + release["tag_name"]
    )
    if not isinstance(commit, dict) or not re.fullmatch(
        r"[0-9a-f]{40}", str(commit.get("sha"))
    ):
        raise InventoryError(
            "latest stable tag could not be resolved to an exact upstream commit"
        )
    return {
        "tag": release["tag_name"],
        "sha": commit["sha"],
        "published_at": release.get("published_at"),
    }


def resolve(repo: Path, ref: str) -> str:
    return git(repo, "rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}")


def commits(repo: Path, revision_range: str) -> list[dict]:
    # NUL separates subjects from metadata; never include patches, bodies or remote URLs.
    raw = git(
        repo,
        "log",
        "--reverse",
        "--topo-order",
        "--format=%H%x00%P%x00%s",
        revision_range,
        "--",
    )
    rows = []
    for line in raw.splitlines():
        sha, parents, subject = line.split("\0", 2)
        rows.append({"sha": sha, "subject": subject, "merge": len(parents.split()) > 1})
    return rows


def equivalents(repo: Path, target: str, source: str, base: str) -> set[str]:
    # git cherry uses patch equivalence, not commit messages or matching file names.
    return {
        line[2:]
        for line in git(repo, "cherry", target, source, base).splitlines()
        if line.startswith("- ")
    }


def inventory(
    repo: Path, fork_ref: str, upstream_ref: str, release: dict | None = None
) -> dict:
    if git(repo, "rev-parse", "--is-shallow-repository") != "false":
        raise InventoryError(
            "shallow history is incomplete; supply a full local repository"
        )
    fork, upstream = resolve(repo, fork_ref), resolve(repo, upstream_ref)
    if release is not None and upstream != release["sha"]:
        raise InventoryError(
            "local stable tag does not match the freshly resolved upstream commit"
        )
    bases = git(repo, "merge-base", "--all", fork, upstream).splitlines()
    if len(bases) != 1:
        raise InventoryError("inventory requires one unambiguous common ancestor")
    base = bases[0]
    upstream_rows = commits(repo, f"{fork}..{upstream}")
    fork_rows = commits(repo, f"{upstream}..{fork}")
    upstream_equal = equivalents(repo, fork, upstream, base)
    fork_equal = equivalents(repo, upstream, fork, base)
    result = {
        "schema": 1,
        "selection": "live_latest_stable" if release else "explicit_offline_ref",
        "release": release,
        "fork": {"ref": fork_ref, "sha": fork},
        "upstream": {"ref": upstream_ref, "sha": upstream},
        "merge_base": base,
        "limitations": [
            "Unmatched commits require review: adapted backports, squashes and dependency fixes may already cover them.",
            "Fix-subject hints are not an exhaustive bug classifier; all unmatched commits are retained.",
            "Patch equivalence does not establish runtime correctness or client adoption.",
            "Merge commits are listed separately; merge conflict resolutions need manual review.",
        ],
        "upstream_review_required": [],
        "upstream_patch_equivalent": [],
        "fork_patch_stack": [],
        "fork_equivalent_backports": [],
        "merges": {"upstream": [], "fork": []},
    }
    for side, rows, equal, unknown_key, equal_key in (
        (
            "upstream",
            upstream_rows,
            upstream_equal,
            "upstream_review_required",
            "upstream_patch_equivalent",
        ),
        (
            "fork",
            fork_rows,
            fork_equal,
            "fork_patch_stack",
            "fork_equivalent_backports",
        ),
    ):
        for row in rows:
            if row.pop("merge"):
                result["merges"][side].append(row)
            elif row["sha"] in equal:
                result[equal_key].append({**row, "status": "patch_equivalent"})
            else:
                result[unknown_key].append(
                    {
                        **row,
                        "status": "review_required",
                        "fix_subject_hint": bool(FIX_HINT.search(row["subject"])),
                    }
                )
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--fork-ref", default="HEAD")
    parser.add_argument(
        "--upstream-ref", help="explicit local ref; disables all network access"
    )
    args = parser.parse_args(argv)
    try:
        release = None
        upstream_ref = args.upstream_ref
        if not upstream_ref:
            release = latest_release()
            upstream_ref = f"refs/tags/{release['tag']}"
        result = inventory(args.repo, args.fork_ref, upstream_ref, release)
    except InventoryError as exc:
        print(f"fork-inventory: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
