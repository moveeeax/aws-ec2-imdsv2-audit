"""The four IMDS rules, and the exit-code decision built from them."""

from __future__ import annotations

import json
from typing import Dict, Iterable, List, Optional, Sequence

from .model import (
    SEVERITY_ORDER,
    Finding,
    Instance,
    LaunchConfiguration,
    RegionInventory,
    TemplateVersion,
)

RULES: Dict[str, str] = {
    "IMDSV1_ENABLED": "high",
    "TEMPLATE_IMDSV1": "high",
    "HOP_LIMIT_TOO_HIGH": "medium",
    "METADATA_ENDPOINT_UNUSED": "low",
}

HARDENED_METADATA = {
    "HttpTokens": "required",
    "HttpEndpoint": "enabled",
    "HttpPutResponseHopLimit": 1,
}


def _template_data(hop_limit: int = 1) -> str:
    payload = dict(HARDENED_METADATA)
    payload["HttpPutResponseHopLimit"] = hop_limit
    return json.dumps({"MetadataOptions": payload}, separators=(",", ":"))


def _modify_instance(region: str, instance_id: str, *args: str) -> str:
    return " ".join(
        [
            "aws ec2 modify-instance-metadata-options",
            f"--region {region}",
            f"--instance-id {instance_id}",
            *args,
        ]
    )


def _new_template_version(version: TemplateVersion) -> str:
    return " ".join(
        [
            "aws ec2 create-launch-template-version",
            f"--region {version.region}",
            f"--launch-template-id {version.template_id}",
            f"--source-version {version.version}",
            f"--launch-template-data '{_template_data()}'",
        ]
    )


def _instance_label(instance: Instance) -> Optional[str]:
    bits = [b for b in (instance.name, instance.asg_name) if b]
    return " / ".join(bits) if bits else None


def _instance_findings(instance: Instance) -> List[Finding]:
    findings: List[Finding] = []
    endpoint_on = instance.http_endpoint == "enabled"

    if endpoint_on and instance.http_tokens != "required":
        origin = ""
        if instance.template_id:
            origin = f", launched from {instance.template_id}"
        elif instance.asg_name:
            origin = f", member of ASG {instance.asg_name}"
        findings.append(
            Finding(
                rule="IMDSV1_ENABLED",
                severity=RULES["IMDSV1_ENABLED"],
                region=instance.region,
                resource_type="instance",
                resource_id=instance.instance_id,
                resource_name=_instance_label(instance),
                detail=(
                    f"HttpTokens={instance.http_tokens}: answers unauthenticated IMDSv1 "
                    f"GETs, so one SSRF reads the instance role credentials "
                    f"(state {instance.state}{origin})"
                ),
                remediation=_modify_instance(
                    instance.region,
                    instance.instance_id,
                    "--http-tokens required",
                    "--http-endpoint enabled",
                ),
            )
        )

    if endpoint_on and instance.hop_limit is not None and instance.hop_limit > 1:
        findings.append(
            Finding(
                rule="HOP_LIMIT_TOO_HIGH",
                severity=RULES["HOP_LIMIT_TOO_HIGH"],
                region=instance.region,
                resource_type="instance",
                resource_id=instance.instance_id,
                resource_name=_instance_label(instance),
                detail=(
                    f"HttpPutResponseHopLimit={instance.hop_limit}: the metadata "
                    "response survives an extra network hop, so containers on a "
                    "bridge network can reach the node role"
                ),
                remediation=_modify_instance(
                    instance.region,
                    instance.instance_id,
                    "--http-put-response-hop-limit 1",
                ),
            )
        )

    if endpoint_on and not instance.has_role:
        findings.append(
            Finding(
                rule="METADATA_ENDPOINT_UNUSED",
                severity=RULES["METADATA_ENDPOINT_UNUSED"],
                region=instance.region,
                resource_type="instance",
                resource_id=instance.instance_id,
                resource_name=_instance_label(instance),
                detail=(
                    "HttpEndpoint=enabled with no instance profile attached: nothing "
                    "on the box needs IMDS, so the endpoint is pure attack surface"
                ),
                remediation=_modify_instance(
                    instance.region, instance.instance_id, "--http-endpoint disabled"
                ),
            )
        )

    return findings


def _template_findings(
    version: TemplateVersion, instance_count: int
) -> List[Finding]:
    meta = version.metadata_options or {}
    findings: List[Finding] = []
    tokens = meta.get("HttpTokens")

    if tokens != "required":
        reason = (
            "no MetadataOptions block"
            if not meta
            else f"HttpTokens={tokens}"
        )
        findings.append(
            Finding(
                rule="TEMPLATE_IMDSV1",
                severity=RULES["TEMPLATE_IMDSV1"],
                region=version.region,
                resource_type="launch-template-version",
                resource_id=f"{version.template_id}:{version.label}",
                resource_name=version.template_name,
                instance_count=instance_count,
                detail=(
                    f"{reason}: every instance this version launches answers IMDSv1, "
                    "so fixing the live instances alone is undone by the next "
                    f"scale-out ({instance_count} collected instance(s) from this template)"
                ),
                remediation=_new_template_version(version),
            )
        )

    hop = meta.get("HttpPutResponseHopLimit")
    if hop is not None and int(hop) > 1:
        findings.append(
            Finding(
                rule="HOP_LIMIT_TOO_HIGH",
                severity=RULES["HOP_LIMIT_TOO_HIGH"],
                region=version.region,
                resource_type="launch-template-version",
                resource_id=f"{version.template_id}:{version.label}",
                resource_name=version.template_name,
                instance_count=instance_count,
                detail=(
                    f"HttpPutResponseHopLimit={hop}: new instances start with the "
                    "extra hop already allowed"
                ),
                remediation=_new_template_version(version),
            )
        )
    return findings


def _launch_configuration_findings(config: LaunchConfiguration) -> List[Finding]:
    meta = config.metadata_options or {}
    if meta.get("HttpTokens") == "required":
        return []
    reason = "no MetadataOptions block" if not meta else f"HttpTokens={meta.get('HttpTokens')}"
    data = _template_data()
    return [
        Finding(
            rule="TEMPLATE_IMDSV1",
            severity=RULES["TEMPLATE_IMDSV1"],
            region=config.region,
            resource_type="launch-configuration",
            resource_id=config.name,
            detail=(
                f"{reason}: a launch configuration is immutable, so the ASG using it "
                "keeps minting IMDSv1 instances until it moves to a launch template"
            ),
            remediation=(
                "aws ec2 create-launch-template "
                f"--region {config.region} "
                f"--launch-template-name {config.name}-imdsv2 "
                f"--launch-template-data '{data}'"
            ),
        )
    ]


def _instances_per_template(inventory: RegionInventory) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for instance in inventory.instances:
        if instance.template_id:
            counts[instance.template_id] = counts.get(instance.template_id, 0) + 1
    return counts


def evaluate(
    inventories: Iterable[RegionInventory], ignore: Sequence[str] = ()
) -> List[Finding]:
    ignored = {rule.strip().upper() for rule in ignore if rule.strip()}
    findings: List[Finding] = []
    for inventory in inventories:
        counts = _instances_per_template(inventory)
        for instance in inventory.instances:
            findings.extend(_instance_findings(instance))
        for version in inventory.template_versions:
            findings.extend(
                _template_findings(version, counts.get(version.template_id, 0))
            )
        for config in inventory.launch_configurations:
            findings.extend(_launch_configuration_findings(config))

    findings = [f for f in findings if f.rule not in ignored]
    findings.sort(
        key=lambda f: (
            -SEVERITY_ORDER[f.severity],
            f.region,
            f.rule,
            f.resource_id,
        )
    )
    return findings


def exit_code(findings: Sequence[Finding], fail_on: str) -> int:
    if fail_on == "never":
        return 0
    threshold = SEVERITY_ORDER[fail_on]
    for finding in findings:
        if SEVERITY_ORDER[finding.severity] >= threshold:
            return 1
    return 0
