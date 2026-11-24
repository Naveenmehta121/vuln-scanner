"""
Report builder: turns the list of findings into a readable report.

Two formats:
  * text — printed to the terminal (the default)
  * json — saved to a file with --output, for scripts / CI

Findings are sorted High -> Medium -> Low, with a short summary at the top.
"""

import json
from datetime import datetime, timezone

SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2}


def build_report(target: str, findings: list) -> dict:
    """Wrap the findings in a report dict with a summary and timestamp."""
    counts = {"High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        counts[f["severity"]] += 1
    ordered = sorted(findings, key=lambda f: SEVERITY_ORDER[f["severity"]])
    return {
        "target": target,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total": len(findings),
            "high": counts["High"],
            "medium": counts["Medium"],
            "low": counts["Low"],
        },
        "findings": ordered,
    }


def render_text(report: dict) -> str:
    """Render the report as plain text for the terminal."""
    lines = []
    lines.append("=" * 60)
    lines.append("VulnScanner report")
    lines.append("=" * 60)
    lines.append(f"Target:     {report['target']}")
    lines.append(f"Scanned at: {report['scanned_at']}")
    s = report["summary"]
    lines.append(
        f"Findings:   {s['total']} total — "
        f"{s['high']} High, {s['medium']} Medium, {s['low']} Low"
    )
    lines.append("")

    if not report["findings"]:
        lines.append("No findings. Nothing to fix — nice work!")
        return "\n".join(lines)

    for i, f in enumerate(report["findings"], 1):
        lines.append(f"[{i}] [{f['severity']}] {f['title']}")
        lines.append(f"    Check:  {f['check']}")
        lines.append(f"    Detail: {f['detail']}")
        lines.append(f"    Fix:    {f['fix']}")
        lines.append("")
    return "\n".join(lines)


def save_json(report: dict, path: str) -> None:
    """Save the report as pretty-printed JSON."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
