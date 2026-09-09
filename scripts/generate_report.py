#!/usr/bin/env python3
"""Build three audience-tiered HTML reports from normalized findings.

Usage:
    generate_report.py findings.normalized.json <output_dir> [--previous PATH] [--no-ai]

Writes <output_dir>/report-dev.html, report-manager.html, report-exec.html --
same underlying findings, three different depths, but now ALL THREE also
carry a risk score, compliance-framework percentages, and (when a previous
scan is available) a trend line:
  dev     -- full technical table, every failing check, no AI narrative
             (nothing to translate for this audience -- they want the raw
             detail) -- but score/compliance/trend are shown here too.
  manager -- AI-written summary (specific: which accounts/services, what's
             trending) + a condensed table of the top findings.
  exec    -- AI-written summary only, most abstracted, no table.

`--previous` is the prior run's normalized findings (see
fetch_previous_scan.py) -- omit it and the trend section just says "first
scan on record."
"""
import html
import json
import sys
from collections import Counter
from pathlib import Path

SEVERITY_ORDER = ["critical", "high", "medium", "low", "unknown"]
SEVERITY_COLOR = {
    "critical": "#b3261e",
    "high": "#c25a00",
    "medium": "#8a6d00",
    "low": "#3d6b3d",
    "unknown": "#5f6368",
}
SEVERITY_WEIGHT = {"critical": 10, "high": 5, "medium": 2, "low": 1, "unknown": 2}
# Scales average penalty-per-check into a 0-100 score. Tuned against a real
# 180-check scan (76 aws-full-scan findings across many severities) so a
# genuinely bad account lands well below 50, not pinned at 0 for every
# non-trivial scan -- an earlier version used absolute counts (not
# normalized by total_checks) and returned 0/F regardless of severity.
RISK_SCORE_SCALE = 40

PROFILES = ["dev", "manager", "exec"]

# (label, compliance-key prefix to match, cloud it only applies to or None
# for any cloud). Labels are the real standard names, not generic
# placeholders -- confirmed against real scan compliance dicts:
# AWS-Foundational-Security-Best-Practices is AWS's own curated
# benchmark, but Azure has no equivalent AWS-branded standard --
# Prowler's Azure "best practices" checks map to the CIS Microsoft
# Azure Foundations Benchmark (published by the Center for Internet
# Security, not Microsoft), tagged "CIS-<version>" (e.g. CIS-2.0 ..
# CIS-6.0, one per benchmark version Prowler has metadata for; no
# "-Azure" in the key). "Azure Best Practices" was a placeholder label
# confirmed wrong on 2026-09-08 -- named correctly now, per the user's
# request not to imply a Microsoft-branded standard that doesn't exist.
# Matching "CIS-" is safe even though AWS also carries its own
# "CIS-<version>" tags (CIS AWS Foundations Benchmark), and GCP does too
# (CIS Google Cloud Platform Foundation Benchmark, confirmed for real
# 2026-09-08 against the first live GCP scan: CIS-2.0..CIS-5.0, same
# "CIS-<version>" shape, no cloud name in the key here either) -- the
# cloud_filter below keeps all three from mixing.
COMPLIANCE_FRAMEWORKS = [
    ("PCI-DSS", "PCI-", None),
    ("HIPAA", "HIPAA", None),
    ("AWS Foundational Security Best Practices", "AWS-Foundational-Security-Best-Practices", "aws"),
    ("CIS Azure Foundations Benchmark", "CIS-", "azure"),
    ("CIS Google Cloud Platform Foundation Benchmark", "CIS-", "gcp"),
]


def build_aggregates(findings: list[dict]) -> dict:
    failing = [f for f in findings if f["status"] == "FAIL"]
    by_severity = Counter(f["severity"] for f in failing)
    by_cloud = Counter(f["cloud"] for f in failing)
    top_findings = sorted(
        failing, key=lambda f: SEVERITY_ORDER.index(f["severity"]) if f["severity"] in SEVERITY_ORDER else 9
    )[:5]
    severity_counts = {s: by_severity.get(s, 0) for s in SEVERITY_ORDER}
    score = risk_score(severity_counts, len(findings))
    return {
        "total_checks": len(findings),
        "total_failing": len(failing),
        "by_severity": severity_counts,
        "by_cloud": dict(by_cloud),
        "top_findings": top_findings,
        "risk_score": score,
        "risk_grade": risk_grade(score),
        "compliance": compliance_scores(findings),
    }


def risk_score(by_severity: dict, total_checks: int) -> int:
    """Simple weighted heuristic (100 = clean), not an industry-standard
    scoring model -- deterministic on purpose, so it's comparable run to
    run without an LLM's non-determinism in the way. Normalized by
    total_checks so a bigger scan (more checks = naturally more absolute
    failures) doesn't automatically score worse than a smaller one with the
    same failure *rate*."""
    if total_checks == 0:
        return 100
    weighted = sum(by_severity.get(s, 0) * SEVERITY_WEIGHT[s] for s in SEVERITY_WEIGHT)
    density = weighted / total_checks
    return max(0, min(100, round(100 - density * RISK_SCORE_SCALE)))


def risk_grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def compliance_scores(findings: list[dict]) -> dict:
    """% of checks passing per curated framework, computed from this
    project's own PASS/FAIL findings -- an approximation of framework
    coverage, not the audit-grade score Prowler's own compliance reports
    produce (those track unique control-ID coverage; this counts checks)."""
    scores = {}
    for label, prefix, cloud_filter in COMPLIANCE_FRAMEWORKS:
        relevant = [
            f
            for f in findings
            if f["status"] in ("PASS", "FAIL")
            and any(c.startswith(prefix) for c in f.get("compliance", []))
            and (cloud_filter is None or f["cloud"] == cloud_filter)
        ]
        if not relevant:
            continue
        passing = sum(1 for f in relevant if f["status"] == "PASS")
        scores[label] = {"pct": round(passing / len(relevant) * 100), "passing": passing, "total": len(relevant)}
    return scores


def compute_trend(current: list[dict], previous: list[dict] | None) -> dict | None:
    """Diff two scans' failing checks by (cloud, account, check_id, resource).
    Returns None if there's no previous scan to compare against."""
    if previous is None:
        return None

    def key(f):
        return (f["cloud"], f["account"], f["check_id"], f["resource_id"])

    curr_failing = {key(f): f for f in current if f["status"] == "FAIL"}
    prev_failing = {key(f): f for f in previous if f["status"] == "FAIL"}
    new = [f for k, f in curr_failing.items() if k not in prev_failing]
    resolved = [f for k, f in prev_failing.items() if k not in curr_failing]
    prev_severity = Counter(f["severity"] for f in prev_failing.values())
    prev_score = risk_score({s: prev_severity.get(s, 0) for s in SEVERITY_WEIGHT}, len(previous))
    return {
        "new": new,
        "resolved": resolved,
        "new_count": len(new),
        "resolved_count": len(resolved),
        "previous_risk_score": prev_score,
    }


def build_prompt(aggregates: dict, trend: dict | None, audience: str) -> str:
    top_lines = "\n".join(
        f"- [{f['severity'].upper()}] {f['cloud']}/{f['account']}: {f['title']} -- {f['status_detail']}"
        for f in aggregates["top_findings"]
    )
    compliance_lines = "\n".join(
        f"- {label}: {v['pct']}% ({v['passing']}/{v['total']} checks passing)"
        for label, v in aggregates["compliance"].items()
    ) or "(no compliance framework data matched)"
    context = (
        f"Scan covered {aggregates['total_checks']} checks across "
        f"{', '.join(aggregates['by_cloud'].keys()) or 'no clouds'}. "
        f"{aggregates['total_failing']} checks are failing, broken down by severity as "
        f"{aggregates['by_severity']}. Overall risk score: {aggregates['risk_score']}/100 "
        f"(grade {aggregates['risk_grade']}).\n\n"
        f"Compliance framework coverage:\n{compliance_lines}\n\n"
        f"Top failing findings:\n{top_lines}\n\n"
    )
    if trend is None:
        context += "This is the first scan on record -- there is no prior scan to compare against.\n\n"
    else:
        context += (
            f"Since the last scan: {trend['new_count']} new failing checks, "
            f"{trend['resolved_count']} resolved. Risk score moved from "
            f"{trend['previous_risk_score']} to {aggregates['risk_score']}.\n\n"
        )
    if audience == "manager":
        return context + (
            "Write a 4-5 sentence summary for an engineering manager: name the "
            "specific accounts/clouds and services involved, what's most urgent "
            "and why, reference the compliance percentages and the trend since "
            "last scan if there is one, and what a reasonable next step looks "
            "like. Some technical specificity is fine here -- this reader will "
            "act on it directly."
        )
    return context + (
        "Write a 2-3 sentence executive summary in plain business language (no "
        "acronyms like CIS/NIST/PCI without spelling them out once) for a "
        "non-technical decision-maker: what is the actual business risk, "
        "whether things are getting better or worse since last time, and how "
        "urgent it is. Do not restate every number -- interpret them. No "
        "technical jargon."
    )


def fallback_summary(aggregates: dict, trend: dict | None, audience: str) -> str:
    crit = aggregates["by_severity"]["critical"]
    high = aggregates["by_severity"]["high"]
    clouds = ", ".join(aggregates["by_cloud"].keys()) or "no clouds"
    base = (
        f"This scan checked {aggregates['total_checks']} security controls across {clouds} "
        f"and found {aggregates['total_failing']} failing (risk score {aggregates['risk_score']}/100, "
        f"grade {aggregates['risk_grade']}), including {crit} critical and {high} high-severity issues."
    )
    if trend is not None:
        base += f" Since the last scan: {trend['new_count']} new, {trend['resolved_count']} resolved."
    if audience == "manager":
        base += " See the table below for the specific accounts and checks involved."
    else:
        base += (
            " Critical findings typically mean public exposure of data or an unprotected "
            "admin account -- treat these as this week's priority, not a backlog item."
        )
    return base + " (AI summary unavailable -- showing a templated summary instead; see README.)"


def render_table(findings: list[dict], limit: int | None) -> str:
    failing = sorted(
        (f for f in findings if f["status"] == "FAIL"),
        key=lambda f: SEVERITY_ORDER.index(f["severity"]) if f["severity"] in SEVERITY_ORDER else 9,
    )
    if limit:
        failing = failing[:limit]
    rows = "\n".join(
        f"<tr><td>{html.escape(f['cloud'])}</td><td>{html.escape(f['account'])}</td>"
        f"<td style='color:{SEVERITY_COLOR.get(f['severity'], '#000')}'>{html.escape(f['severity'].upper())}</td>"
        f"<td>{html.escape(f['title'])}</td><td>{html.escape(f['status_detail'])}</td>"
        f"<td>{html.escape(str(f['remediation']))}</td></tr>"
        for f in failing
    )
    return f"""<table>
<tr><th>Cloud</th><th>Account</th><th>Severity</th><th>Check</th><th>Detail</th><th>Remediation</th></tr>
{rows}
</table>"""


def render_score_badge(aggregates: dict) -> str:
    grade_color = {"A": "#3d6b3d", "B": "#5b7d3d", "C": "#8a6d00", "D": "#c25a00", "F": "#b3261e"}
    color = grade_color[aggregates["risk_grade"]]
    return (
        f"<span style='background:{color};color:#fff;padding:6px 14px;border-radius:12px;"
        f"font-size:15px;font-weight:600;margin-right:10px'>Risk score: "
        f"{aggregates['risk_score']}/100 ({aggregates['risk_grade']})</span>"
    )


def render_compliance_row(aggregates: dict) -> str:
    if not aggregates["compliance"]:
        return ""
    chips = "".join(
        f"<span style='background:#eee;color:#333;padding:4px 10px;border-radius:10px;"
        f"margin-right:8px;font-size:13px'>{html.escape(label)}: {v['pct']}% "
        f"({v['passing']}/{v['total']})</span>"
        for label, v in aggregates["compliance"].items()
    )
    return f"<div style='margin-top:10px'>{chips}</div>"


def render_trend_line(aggregates: dict, trend: dict | None) -> str:
    if trend is None:
        return "<p style='color:#666;font-size:13px'>First scan on record -- no trend yet.</p>"
    arrow_new = "&#9650;" if trend["new_count"] else ""
    arrow_resolved = "&#9660;" if trend["resolved_count"] else ""
    delta = aggregates["risk_score"] - trend["previous_risk_score"]
    delta_str = f"+{delta}" if delta > 0 else str(delta)
    return (
        f"<p style='color:#666;font-size:13px'>Since last scan: "
        f"{arrow_new} {trend['new_count']} new &middot; {arrow_resolved} {trend['resolved_count']} resolved "
        f"&middot; risk score {trend['previous_risk_score']} &rarr; {aggregates['risk_score']} ({delta_str})</p>"
    )


def render_html(aggregates: dict, trend: dict | None, findings: list[dict], summary: str, profile: str) -> str:
    severity_badges = "".join(
        f"<span style='background:{SEVERITY_COLOR[s]};color:#fff;padding:4px 10px;"
        f"border-radius:12px;margin-right:8px;font-size:13px'>{s.upper()}: {aggregates['by_severity'][s]}</span>"
        for s in SEVERITY_ORDER
        if aggregates["by_severity"][s] > 0
    )
    titles = {
        "dev": "Multi-cloud security scan -- technical detail",
        "manager": "Multi-cloud security scan -- team summary",
        "exec": "Multi-cloud security scan -- executive summary",
    }
    body_extra = ""
    if profile == "dev":
        body_extra = f"<h2>Every failing check</h2>{render_table(findings, limit=None)}"
    elif profile == "manager":
        body_extra = (
            f'<div class="summary"><strong>Summary</strong><p>{html.escape(summary)}</p></div>'
            f"<h2>Top findings</h2>{render_table(findings, limit=10)}"
        )
    else:
        body_extra = f'<div class="summary"><strong>Summary</strong><p>{html.escape(summary)}</p></div>'

    return f"""<!doctype html>
<html><head><meta charset="utf-8">
<title>{titles[profile]}</title>
<style>
body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 40px; color: #1a1a1a; }}
h1 {{ font-size: 22px; }}
.summary {{ background: #f4f4f4; border-left: 4px solid #333; padding: 16px 20px; margin: 20px 0; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
th, td {{ border: 1px solid #ddd; padding: 8px 10px; font-size: 13px; text-align: left; vertical-align: top; }}
th {{ background: #eee; }}
</style></head>
<body>
<h1>{titles[profile]}</h1>
<p>{aggregates['total_checks']} checks run &middot; {aggregates['total_failing']} failing</p>
<div>{render_score_badge(aggregates)}{severity_badges}</div>
{render_compliance_row(aggregates)}
{render_trend_line(aggregates, trend)}
{body_extra}
</body></html>"""


def summarize_for(aggregates: dict, trend: dict | None, audience: str, use_ai: bool) -> str:
    if not use_ai:
        return fallback_summary(aggregates, trend, audience)
    try:
        import llm_client

        return llm_client.summarize(build_prompt(aggregates, trend, audience))
    except Exception as exc:  # noqa: BLE001 - degrade to template, never fail the report
        print(f"[warn] AI summary failed for {audience} ({exc}); using fallback summary", file=sys.stderr)
        return fallback_summary(aggregates, trend, audience)


def main(findings_path: str, output_dir: str, previous_path: str | None, use_ai: bool) -> dict[str, str]:
    with open(findings_path) as f:
        findings = json.load(f)

    previous = None
    if previous_path and Path(previous_path).exists():
        with open(previous_path) as f:
            previous = json.load(f)

    aggregates = build_aggregates(findings)
    trend = compute_trend(findings, previous)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    paths = {}
    for profile in PROFILES:
        summary = "" if profile == "dev" else summarize_for(aggregates, trend, profile, use_ai)
        report = render_html(aggregates, trend, findings, summary, profile)
        path = out / f"report-{profile}.html"
        path.write_text(report)
        paths[profile] = str(path)
        print(f"wrote {path}")

    print(
        f"({aggregates['total_failing']} failing / {aggregates['total_checks']} checks, "
        f"risk score {aggregates['risk_score']}/{aggregates['risk_grade']})"
    )
    return paths


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    previous_arg = None
    if "--previous" in sys.argv:
        previous_arg = sys.argv[sys.argv.index("--previous") + 1]
        args = [a for a in args if a != previous_arg]
    if len(args) != 2:
        sys.exit("usage: generate_report.py <findings.normalized.json> <output_dir> [--previous PATH] [--no-ai]")
    main(args[0], args[1], previous_arg, use_ai="--no-ai" not in sys.argv)
