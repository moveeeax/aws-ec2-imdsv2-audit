"""Plain data holders shared by collection, rules and reporting."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}
SEVERITIES = ("high", "medium", "low")


@dataclass
class Instance:
    instance_id: str
    region: str
    state: str
    http_tokens: str
    http_endpoint: str
    hop_limit: Optional[int]
    metadata_state: str
    has_role: bool
    name: Optional[str] = None
    template_id: Optional[str] = None
    template_version: Optional[str] = None
    asg_name: Optional[str] = None


@dataclass
class TemplateVersion:
    region: str
    template_id: str
    template_name: str
    version: int
    labels: List[str] = field(default_factory=list)
    metadata_options: Optional[Dict[str, Any]] = None

    @property
    def label(self) -> str:
        if not self.labels:
            return str(self.version)
        return f"{self.version} ({', '.join(self.labels)})"


@dataclass
class LaunchConfiguration:
    region: str
    name: str
    metadata_options: Optional[Dict[str, Any]] = None


@dataclass
class RegionInventory:
    region: str
    instances: List[Instance] = field(default_factory=list)
    template_versions: List[TemplateVersion] = field(default_factory=list)
    launch_configurations: List[LaunchConfiguration] = field(default_factory=list)


@dataclass
class Finding:
    rule: str
    severity: str
    region: str
    resource_type: str
    resource_id: str
    detail: str
    remediation: str
    resource_name: Optional[str] = None
    instance_count: Optional[int] = None

    def as_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
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
