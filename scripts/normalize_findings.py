#!/usr/bin/env python3
"""Merge one or more Prowler finding JSON files into one common schema.

Usage:
    normalize_findings.py aws.json azure.json > findings.normalized.json

Each input file is a JSON array of Prowler OCSF findings -- either real
output from `prowler <provider> --output-modes json-ocsf` (Prowler's default
export shape as of v5, confirmed against a real scan) or the sample files
under sample-data/, which are hand-built in the same shape.
"""
import json
import sys


def normalize(raw: dict) -> dict:
    resources = raw.get("resources") or [{}]
    resource = resources[0]
    return {
        "cloud": raw.get("cloud", {}).get("provider", "unknown"),
        "account": raw.get("cloud", {}).get("account", {}).get("uid", "unknown"),
        "region": raw.get("cloud", {}).get("region", "unknown"),
        "check_id": raw.get("finding_info", {}).get("analytic", {}).get("uid", ""),
        "title": raw.get("finding_info", {}).get("title", ""),
        "service": raw.get("finding_info", {}).get("analytic", {}).get("category", ""),
        "status": raw.get("status_code", "UNKNOWN"),
        "status_detail": raw.get("status_detail", ""),
        "severity": raw.get("severity", "unknown").lower(),
        "resource_type": resource.get("type", ""),
        "resource_id": resource.get("uid", resource.get("name", "")),
        "risk": raw.get("risk_details", ""),
        "remediation": raw.get("remediation", {}).get("desc", ""),
        "compliance": sorted((raw.get("unmapped") or {}).get("compliance", {}).keys()),
    }


def main(paths: list[str]) -> None:
    merged = []
    for path in paths:
        with open(path) as f:
            raw_findings = json.load(f)
        merged.extend(normalize(item) for item in raw_findings)
    json.dump(merged, sys.stdout, indent=2)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: normalize_findings.py <file1.json> [file2.json ...]")
    main(sys.argv[1:])
