"""Run kinds, in one place so that no filter is left behind when one is added."""

# Full scans of an asset: whatever a new one no longer reports counts as remediated.
FULL_SCANS = ("repository_scan", "image_scan")
# Advisories published after the last scan, checked against its dependencies (advisory_watch). They only add:
# they are not a full scan and remediate nothing.
ADVISORY_RUNS = ("advisory_watch",)
# Everything that feeds the findings registry and accepts triage.
FINDING_RUNS = FULL_SCANS + ("pr_review",) + ADVISORY_RUNS
