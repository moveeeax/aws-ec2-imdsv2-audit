"""table / json / csv rendering of findings."""

from __future__ import annotations

import csv
import io
import json
from typing import Dict, List, Sequence

from .model import SEVERITIES, Finding, RegionInventory

COLUMNS = ("SEVERITY", "RULE", "REGION", "RESOURCE", "DETAIL")
CSV_COLUMNS = (
    "severity",
    "rule",
    "region",
    "resource_type",
    "resource_id",
    "resource_name",
    "instance_count",
    "detail",
    "remediation",
)


def counts_by_severity(findings: Sequence[Finding]) -> Dict[str, int]:
    counts = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        counts[finding.severity] += 1
    return counts


def scanned_summary(inventories: Sequence[RegionInventory]) -> Dict[str, object]:
    return {
        "regions": [inv.region for inv in inventories],
        "instances": sum(len(inv.instances) for inv in inventories),
        "launch_template_versions": sum(
            len(inv.template_versions) for inv in inventories
        ),
        "launch_configurations": sum(
            len(inv.launch_configurations) for inv in inventories
        ),
    }


def _truncate(text: str, width: int) -> str:
    if len(text) <= width:
        return text
    return text[: width - 1] + "…"


def render_table(
    findings: Sequence[Finding], inventories: Sequence[RegionInventory]
) -> str:
    scanned = scanned_summary(inventories)
    header = (
        f"Scanned {scanned['instances']} instance(s), "
        f"{scanned['launch_template_versions']} launch template version(s), "
        f"{scanned['launch_configurations']} launch configuration(s) "
        f"in {', '.join(scanned['regions'])}"
    )
    if not findings:
        return header + "\n\nNo findings: IMDSv1 is not reachable anywhere scanned."

    rows: List[Sequence[str]] = []
    for finding in findings:
        resource = finding.resource_id
        if finding.resource_name and finding.resource_name != finding.resource_id:
            resource = f"{resource} ({finding.resource_name})"
        rows.append(
            (
                finding.severity.upper(),
                finding.rule,
                finding.region,
                resource,
                _truncate(finding.detail, 72),
            )
        )

    widths = [len(col) for col in COLUMNS]
    for row in rows:
        widths = [max(w, len(cell)) for w, cell in zip(widths, row)]

    lines = [header, ""]
    lines.append("  ".join(col.ljust(w) for col, w in zip(COLUMNS, widths)).rstrip())
    lines.append("  ".join("-" * w for w in widths))
    for row in rows:
        lines.append("  ".join(cell.ljust(w) for cell, w in zip(row, widths)).rstrip())

    lines.append("")
    lines.append("Remediation")
    for finding in findings:
        lines.append(f"  {finding.rule} {finding.resource_id}")
        lines.append(f"    {finding.remediation}")

    counts = counts_by_severity(findings)
    lines.append("")
    lines.append(
        "Findings: "
        + ", ".join(f"{counts[severity]} {severity}" for severity in SEVERITIES)
    )
    return "\n".join(lines)


def render_json(
    findings: Sequence[Finding], inventories: Sequence[RegionInventory]
) -> str:
    payload = {
        "scanned": scanned_summary(inventories),
        "summary": counts_by_severity(findings),
        "findings": [finding.as_dict() for finding in findings],
    }
    return json.dumps(payload, indent=2, sort_keys=False)


def render_csv(findings: Sequence[Finding]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    for finding in findings:
        data = finding.as_dict()
        writer.writerow([data.get(column, "") for column in CSV_COLUMNS])
    return buffer.getvalue().rstrip("\n")


def render(
    fmt: str, findings: Sequence[Finding], inventories: Sequence[RegionInventory]
) -> str:
    if fmt == "json":
        return render_json(findings, inventories)
    if fmt == "csv":
        return render_csv(findings)
    return render_table(findings, inventories)
