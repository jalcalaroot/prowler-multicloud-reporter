#!/usr/bin/env python3
"""Upload the 3 tiered reports (+ normalized findings) to cloud storage under
one run prefix, and print a time-limited link for each report.

Usage:
    publish_reports.py <reports_dir> <run_id>

Backend (S3 or Azure Blob) comes from storage_backend.py, selected by
STORAGE_BACKEND -- same pattern as llm_client.py's LLM_BACKEND. Both
buckets/containers are private (see infra/aws and infra/azure); these are
signed, time-limited links, not a public website.

Also writes the current findings to a stable `latest/findings.normalized.json`
key (overwriting whatever was there) *after* everything else is uploaded --
that's what fetch_previous_scan.py reads on the *next* run to compute the
trend between scans. Uploading the per-run copy under runs/<run_id>/ as well
means every run leaves a queryable history behind almost for free.
"""
import os
import sys

import storage_backend

PROFILES = ["dev", "manager", "exec"]
LATEST_FINDINGS_KEY = "latest/findings.normalized.json"


def _expiry_seconds() -> int:
    # GitHub Actions sets an unset `vars.*` as an empty string, not an absent
    # env var -- os.environ.get()'s default only kicks in when the key is
    # missing entirely, so an explicit `or` is needed here (confirmed for
    # real 2026-09-06: this crashed with ValueError: invalid literal for
    # int() with base 10: '' in the actual workflow run).
    return int(os.environ.get("REPORT_URL_EXPIRY_SECONDS") or 7 * 24 * 3600)


def main(reports_dir: str, run_id: str) -> None:
    findings_path = os.path.join(reports_dir, "findings.normalized.json")
    if os.path.exists(findings_path):
        storage_backend.upload(findings_path, f"runs/{run_id}/findings.normalized.json", "application/json")

    urls = {}
    for profile in PROFILES:
        local_path = os.path.join(reports_dir, f"report-{profile}.html")
        if not os.path.exists(local_path):
            continue
        key = f"runs/{run_id}/report-{profile}.html"
        storage_backend.upload(local_path, key, "text/html")
        urls[profile] = storage_backend.signed_url(key, _expiry_seconds())

    # Update the "latest" pointer last, so fetch_previous_scan.py always sees
    # a fully-uploaded prior run, never a half-written one.
    if os.path.exists(findings_path):
        storage_backend.upload(findings_path, LATEST_FINDINGS_KEY, "application/json")

    lines = [f"## Report links ({storage_backend.backend_name()}, expire in {_expiry_seconds() // 3600}h)"]
    lines += [f"- **{profile}**: {url}" for profile, url in urls.items()]
    output = "\n".join(lines)
    print(output)

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a") as f:
            f.write(output + "\n")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: publish_reports.py <reports_dir> <run_id>")
    main(sys.argv[1], sys.argv[2])
