# Security Policy

This tool runs read-only security scans (Prowler) against real AWS and Azure accounts and handles the resulting findings. There are no supported version branches — only `main` is maintained.

## Reporting a Vulnerability

If you find a security issue — an exposed secret, a leaked credential in git history, a finding/report that leaked somewhere it shouldn't, or a vulnerable dependency — please report it privately using [GitHub's private vulnerability reporting](../../security/advisories/new) instead of opening a public issue.

## Scope

- This repository's own code (`scripts/`, the GitHub Actions workflows) and how it handles cloud credentials and scan output.
- Accidentally committed findings, reports, `.env` files, or other secrets.

Out of scope: vulnerabilities in Prowler itself, the underlying cloud providers, or [llamafile](https://github.com/Mozilla-Ocho/llamafile) (the local model runtime used for AI summaries) — please report those to their respective maintainers.

## Design notes relevant to security review

- Cloud scanning is meant to run via OIDC (no static AWS/Azure credentials as GitHub secrets) — see `README.md`.
- The LLM step (`scripts/llm_client.py`) is given only aggregated finding counts and a short top-findings list, never raw cloud credentials or account access, and is instructed not to invent or reclassify findings.
- Reports are delivered as signed, time-limited links from a private S3 bucket or Blob container (`scripts/publish_reports.py`) — never a public bucket/static site — and auto-expire via a lifecycle policy. There is no email delivery in this project.
- Scan output and generated reports are gitignored (the whole `reports/` directory) — only the fictional `sample-data/` is meant to be committed.
