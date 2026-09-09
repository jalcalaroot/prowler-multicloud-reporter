#!/usr/bin/env python3
"""Download the previous run's normalized findings, if one exists, so
generate_report.py can compute a trend ("what changed since last scan").

Usage:
    fetch_previous_scan.py <output_path>

Exits 0 either way. Prints whether a previous run was found; the caller
(generate_report.py) treats a missing output file as "first scan, no trend."
"""
import sys

import storage_backend

LATEST_FINDINGS_KEY = "latest/findings.normalized.json"


def main(output_path: str) -> None:
    found = storage_backend.download(LATEST_FINDINGS_KEY, output_path)
    print("previous run found" if found else "no previous run on record (first scan)")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: fetch_previous_scan.py <output_path>")
    main(sys.argv[1])
