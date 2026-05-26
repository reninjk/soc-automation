#!/usr/bin/env python3
"""
Weekly SOC Metrics Report Generator

Pulls alert/incident data and generates a structured weekly metrics report
in both JSON and Markdown formats.

Usage:
    python weekly_metrics.py --week 2026-W03
    python weekly_metrics.py --start 2026-01-13 --end 2026-01-19
    python weekly_metrics.py  # defaults to current week
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import structlog
from dotenv import load_dotenv

load_dotenv()

# ─── Logging ─────────────────────────────────────────────────────────────────

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.ConsoleRenderer(),
    ]
)
log = structlog.get_logger()


# ─── Data Collection (stub — wire to your SIEM/ticketing system) ─────────────

def get_alert_stats(start: datetime, end: datetime) -> dict:
    """
    Pull alert statistics from SIEM for the given period.
    Wire this to your SIEM API (Splunk, Sentinel, Elastic).
    Returns stub data if API not configured.
    """
    siem_url = os.getenv("SIEM_URL")
    if not siem_url:
        log.warning("SIEM_URL not set — returning sample data for demo")
        return _sample_alert_data()

    # TODO: implement actual SIEM query
    # Example Splunk query:
    # search index=alerts earliest={start} latest={end}
    # | stats count as total, count(eval(severity="critical")) as critical ...
    raise NotImplementedError("Wire get_alert_stats() to your SIEM API")


def get_incident_stats(start: datetime, end: datetime) -> dict:
    """
    Pull incident statistics from ticketing system.
    Wire to Jira, ServiceNow, or TheHive.
    """
    ticketing_url = os.getenv("JIRA_URL") or os.getenv("SNOW_INSTANCE") or os.getenv("THEHIVE_URL")
    if not ticketing_url:
        log.warning("Ticketing system not configured — returning sample data")
        return _sample_incident_data()
    raise NotImplementedError("Wire get_incident_stats() to your ticketing system API")


def _sample_alert_data() -> dict:
    """Sample data for demo/testing purposes."""
    return {
        "total_alerts": 847,
        "true_positives": 312,
        "false_positives": 535,
        "false_positive_rate_pct": 63.2,
        "by_severity": {
            "critical": 12,
            "high": 87,
            "medium": 298,
            "low": 450,
        },
        "top_rules": [
            {"rule": "brute-force-login", "count": 145, "fp_rate_pct": 82},
            {"rule": "powershell-encoded-cmd", "count": 67, "fp_rate_pct": 31},
            {"rule": "scheduled-task-creation", "count": 54, "fp_rate_pct": 45},
            {"rule": "network-recon", "count": 43, "fp_rate_pct": 76},
            {"rule": "office-macro-execution", "count": 38, "fp_rate_pct": 18},
        ],
        "escalated_to_l2": 89,
        "auto_closed": 412,
        "alerts_per_analyst_per_day": 42.3,
    }


def _sample_incident_data() -> dict:
    """Sample data for demo/testing purposes."""
    return {
        "total_declared": 14,
        "by_priority": {"P1": 1, "P2": 3, "P3": 7, "P4": 3},
        "closed": 12,
        "open": 2,
        "avg_mttd_minutes": {"P1": 8, "P2": 22, "P3": 47, "all": 31},
        "avg_mttr_hours": {"P1": 0.8, "P2": 3.2, "P3": 18.4, "all": 11.2},
        "sla_compliance_pct": 92.8,
        "by_type": {
            "phishing": 5,
            "malware": 3,
            "account_compromise": 2,
            "brute_force": 2,
            "policy_violation": 2,
        },
    }


# ─── Metrics Calculation ─────────────────────────────────────────────────────

def calculate_rag_status(metric_name: str, value: float) -> str:
    """Return RAG status for a given metric."""
    thresholds = {
        "false_positive_rate_pct": {"green": 30, "amber": 50},  # lower = better
        "sla_compliance_pct": {"green": 95, "amber": 85},       # higher = better
        "avg_mttd_p1_minutes": {"green": 10, "amber": 20},      # lower = better
        "avg_mttr_p1_hours": {"green": 1, "amber": 2},          # lower = better
        "alerts_per_analyst_per_day": {"green": 60, "amber": 80}, # lower = better
    }
    t = thresholds.get(metric_name)
    if not t:
        return "⚪ N/A"
    if metric_name in ("sla_compliance_pct",):
        # Higher is better
        if value >= t["green"]: return "🟢 GREEN"
        if value >= t["amber"]: return "🟡 AMBER"
        return "🔴 RED"
    else:
        # Lower is better
        if value <= t["green"]: return "🟢 GREEN"
        if value <= t["amber"]: return "🟡 AMBER"
        return "🔴 RED"


# ─── Report Generation ────────────────────────────────────────────────────────

def generate_markdown_report(
    week_label: str,
    start: datetime,
    end: datetime,
    alerts: dict,
    incidents: dict,
) -> str:
    """Generate a Markdown weekly metrics report."""
    fp_rag = calculate_rag_status("false_positive_rate_pct", alerts["false_positive_rate_pct"])
    sla_rag = calculate_rag_status("sla_compliance_pct", incidents["sla_compliance_pct"])
    mttd_rag = calculate_rag_status("avg_mttd_p1_minutes", incidents["avg_mttd_minutes"]["P1"])
    mttr_rag = calculate_rag_status("avg_mttr_p1_hours", incidents["avg_mttr_hours"]["P1"])

    top_rules_table = "\n".join([
        f"| {r['rule']} | {r['count']} | {r['fp_rate_pct']}% |"
        for r in alerts.get("top_rules", [])
    ])

    return f"""# Weekly SOC Metrics Report — {week_label}
**Period:** {start.strftime('%Y-%m-%d')} to {end.strftime('%Y-%m-%d')}
**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}
**Prepared By:** SOC Automation (weekly_metrics.py)

---

## Dashboard

| Metric | Value | Status |
|--------|-------|--------|
| Total Alerts | {alerts['total_alerts']} | |
| False Positive Rate | {alerts['false_positive_rate_pct']:.1f}% | {fp_rag} |
| Incidents Declared | {incidents['total_declared']} | |
| SLA Compliance | {incidents['sla_compliance_pct']:.1f}% | {sla_rag} |
| MTTD (P1) | {incidents['avg_mttd_minutes']['P1']} min | {mttd_rag} |
| MTTR (P1) | {incidents['avg_mttr_hours']['P1']:.1f} hrs | {mttr_rag} |
| Alerts per Analyst/Day | {alerts['alerts_per_analyst_per_day']:.1f} | |

---

## Alert Volume

| Severity | Count | % of Total |
|----------|-------|-----------|
| Critical | {alerts['by_severity']['critical']} | {alerts['by_severity']['critical']/alerts['total_alerts']*100:.1f}% |
| High | {alerts['by_severity']['high']} | {alerts['by_severity']['high']/alerts['total_alerts']*100:.1f}% |
| Medium | {alerts['by_severity']['medium']} | {alerts['by_severity']['medium']/alerts['total_alerts']*100:.1f}% |
| Low | {alerts['by_severity']['low']} | {alerts['by_severity']['low']/alerts['total_alerts']*100:.1f}% |
| **Total** | **{alerts['total_alerts']}** | 100% |

**True Positives:** {alerts['true_positives']} | **False Positives:** {alerts['false_positives']}

## Top 5 Alert Rules

| Rule | Count | FP Rate |
|------|-------|---------|
{top_rules_table}

---

## Incidents

| Priority | Count |
|----------|-------|
| P1 — Critical | {incidents['by_priority']['P1']} |
| P2 — High | {incidents['by_priority']['P2']} |
| P3 — Medium | {incidents['by_priority']['P3']} |
| P4 — Low | {incidents['by_priority']['P4']} |
| **Total** | **{incidents['total_declared']}** |

**Open:** {incidents['open']} | **Closed:** {incidents['closed']}

## Response Times

| Priority | Avg MTTD | Target | Avg MTTR | Target |
|----------|----------|--------|----------|--------|
| P1 | {incidents['avg_mttd_minutes']['P1']} min | 10 min | {incidents['avg_mttr_hours']['P1']:.1f} hrs | 1 hr |
| P2 | {incidents['avg_mttd_minutes']['P2']} min | 15 min | {incidents['avg_mttr_hours']['P2']:.1f} hrs | 4 hrs |
| P3 | {incidents['avg_mttd_minutes']['P3']} min | 30 min | {incidents['avg_mttr_hours']['P3']:.1f} hrs | 24 hrs |

---

*Report generated automatically. Review and add narrative before distributing.*
*Template: [weekly-report-template.md](https://github.com/reninjk/soc-compliance-reporting/blob/main/reporting/weekly-report-template.md)*
"""


def generate_json_report(
    week_label: str, start: datetime, end: datetime, alerts: dict, incidents: dict
) -> dict:
    """Generate structured JSON report for programmatic consumption."""
    return {
        "report_type": "weekly_metrics",
        "week": week_label,
        "period": {"start": start.isoformat(), "end": end.isoformat()},
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "alerts": alerts,
        "incidents": incidents,
        "rag_status": {
            "false_positive_rate": calculate_rag_status("false_positive_rate_pct", alerts["false_positive_rate_pct"]),
            "sla_compliance": calculate_rag_status("sla_compliance_pct", incidents["sla_compliance_pct"]),
            "mttd_p1": calculate_rag_status("avg_mttd_p1_minutes", incidents["avg_mttd_minutes"]["P1"]),
            "mttr_p1": calculate_rag_status("avg_mttr_p1_hours", incidents["avg_mttr_hours"]["P1"]),
        },
    }


# ─── CLI Entry Point ──────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(description="Generate weekly SOC metrics report")
    parser.add_argument("--week", help="ISO week label e.g. 2026-W03")
    parser.add_argument("--start", help="Start date YYYY-MM-DD")
    parser.add_argument("--end", help="End date YYYY-MM-DD")
    parser.add_argument("--output", default="./reports", help="Output directory")
    parser.add_argument("--format", choices=["markdown", "json", "both"], default="both")
    return parser.parse_args()


def resolve_dates(args) -> tuple[datetime, datetime, str]:
    if args.start and args.end:
        start = datetime.fromisoformat(args.start).replace(tzinfo=timezone.utc)
        end = datetime.fromisoformat(args.end).replace(tzinfo=timezone.utc)
        week_label = f"{start.strftime('%Y-%m-%d')} to {end.strftime('%Y-%m-%d')}"
    else:
        # Default: current ISO week (Mon–Sun)
        today = datetime.now(timezone.utc)
        start = today - timedelta(days=today.weekday())
        start = start.replace(hour=0, minute=0, second=0, microsecond=0)
        end = start + timedelta(days=6, hours=23, minutes=59, seconds=59)
        week_label = f"{today.strftime('%Y')}-W{today.isocalendar()[1]:02d}"
        if args.week:
            week_label = args.week
    return start, end, week_label


def main():
    args = parse_args()
    start, end, week_label = resolve_dates(args)

    log.info("generating_weekly_report", week=week_label, start=str(start.date()), end=str(end.date()))

    # Collect data
    alerts = get_alert_stats(start, end)
    incidents = get_incident_stats(start, end)

    # Ensure output directory exists
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    safe_label = week_label.replace(" ", "_").replace("/", "-")

    # Write outputs
    if args.format in ("markdown", "both"):
        md_path = output_dir / f"weekly_metrics_{safe_label}.md"
        md_content = generate_markdown_report(week_label, start, end, alerts, incidents)
        md_path.write_text(md_content)
        log.info("report_written", path=str(md_path))
        print(md_content)

    if args.format in ("json", "both"):
        json_path = output_dir / f"weekly_metrics_{safe_label}.json"
        json_data = generate_json_report(week_label, start, end, alerts, incidents)
        json_path.write_text(json.dumps(json_data, indent=2))
        log.info("json_written", path=str(json_path))

    log.info("report_complete", week=week_label)


if __name__ == "__main__":
    main()
