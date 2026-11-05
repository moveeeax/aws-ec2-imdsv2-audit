"""Plain data holders shared by collection, rules and reporting."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}
SEVERITIES = ("high", "medium", "low")


@dataclass
class Instance:
    instance_id: str
    region: str
    state: str
    http_tokens: str
    http_endpoint: str
    hop_limit: int | None
    metadata_state: str
    has_role: bool
    name: str | None = None
    template_id: str | None = None
    template_version: str | None = None
    asg_name: str | None = None


@dataclass
class TemplateVersion:
    region: str
    template_id: str
    template_name: str
    version: int
    labels: list[str] = field(default_factory=list)
    metadata_options: dict[str, Any] | None = None

    @property
    def label(self) -> str:
        if not self.labels:
            return str(self.version)
        return f"{self.version} ({', '.join(self.labels)})"


@dataclass
class LaunchConfiguration:
    region: str
    name: str
    metadata_options: dict[str, Any] | None = None


@dataclass
class RegionInventory:
    region: str
    instances: list[Instance] = field(default_factory=list)
    template_versions: list[TemplateVersion] = field(default_factory=list)
    launch_configurations: list[LaunchConfiguration] = field(default_factory=list)


@dataclass
class Finding:
    rule: str
    severity: str
    region: str
    resource_type: str
    resource_id: str
    detail: str
    remediation: str
    resource_name: str | None = None
    instance_count: int | None = None

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "rule": self.rule,
            "severity": self.severity,
            "region": self.region,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "detail": self.detail,
            "remediation": self.remediation,
        }
        if self.resource_name:
            out["resource_name"] = self.resource_name
        if self.instance_count is not None:
            out["instance_count"] = self.instance_count
        return out


class AwsAuditError(Exception):
    """An AWS API, credential or configuration problem. Exits 2, never a traceback."""
