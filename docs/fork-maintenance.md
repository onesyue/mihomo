# Reviewing the fork patch stack

Run `python3 tools/fork_inventory.py > inventory.json` from a full mihomo checkout.
The default queries the current stable release from MetaCubeX/mihomo on every
invocation and resolves the release tag to its exact upstream commit. The local
tag must resolve to that same commit. Missing
history, a missing tag, an invalid release response or network failure exits
nonzero; an old cached release is never silently substituted. Obtain missing
history separately using your normal reviewed repository workflow.

For a reproducible offline comparison, specify both reviewed refs:

```sh
python3 tools/fork_inventory.py --fork-ref HEAD --upstream-ref refs/tags/v1.19.34 > inventory.json
python3 -m unittest discover -s tools -p 'test_fork_inventory.py'
```

The report records resolved commit hashes and a unique merge base. It lists:

- `upstream_review_required`: upstream changes absent from fork ancestry and
  without equivalent patches. A fix-subject hint prioritizes triage, but every
  unmatched commit is retained, including dependency bumps and feature commits.
- `upstream_patch_equivalent` and `fork_equivalent_backports`: equivalent
  non-merge changes detected by `git cherry` rather than commit-message matching.
- `fork_patch_stack`: residual local changes that require a retention/removal
  decision. This includes runtime, test, build and documentation changes; it is
  not a count of runtime modifications.
- `merges`: integration commits on both sides, separately from patch counts.
  Conflict resolutions within merges require manual review.

`review_required` means unknown, not a confirmed missing fix. Adapted backports,
squashed changes and dependency fixes can have different patches but equivalent
behavior. Compare source and regression evidence before deciding a fix is
absent. Patch equivalence alone also does not establish runtime correctness.

Use the consumer's `docs/governance/mihomo-fork-ledger.json` and companion rebase
checklist as the reviewed retention record. For each unmatched change record the
exact upstream SHA, fork SHA, reason, regression evidence and intended action:
retain local behavior, backport narrowly, already covered, or explicitly defer.
Preserve maintained dependency replacements and mobile gVisor behavior until
their replacement is separately qualified. Shrinking the fork means retiring
verified redundant patches, not deleting everything lacking a matching subject.

This command reads Git history and public release metadata only. It never
fetches, changes refs, applies patches, cherry-picks, merges, pushes, edits the
consumer ledger or runs builds/devices. JSON contains public commit subjects
and hashes, not diffs, commit bodies, credentials or repository remote URLs.
An explicit upstream ref disables all network calls and yields deterministic
output for the same Git objects. Review the inventory as a separate small PR;
it is not authorization to merge, release or change production.
