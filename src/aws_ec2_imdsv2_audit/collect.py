"""Collect metadata configuration from EC2 and Auto Scaling."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

from botocore.exceptions import BotoCoreError, ClientError

from .model import (
    AwsAuditError,
    Instance,
    LaunchConfiguration,
    RegionInventory,
    TemplateVersion,
)

TEMPLATE_ID_TAG = "aws:ec2launchtemplate:id"
TEMPLATE_VERSION_TAG = "aws:ec2launchtemplate:version"
ASG_TAG = "aws:autoscaling:groupName"

RUNNING_STATES = ["running"]
STOPPED_STATES = ["stopped", "stopping"]


def _tags(raw: Iterable[Dict[str, str]]) -> Dict[str, str]:
    return {t.get("Key", ""): t.get("Value", "") for t in raw or []}


def _instance_from_api(raw: Dict[str, Any], region: str) -> Instance:
    meta = raw.get("MetadataOptions") or {}
    tags = _tags(raw.get("Tags"))
    hop = meta.get("HttpPutResponseHopLimit")
    return Instance(
        instance_id=raw["InstanceId"],
        region=region,
        state=(raw.get("State") or {}).get("Name", "unknown"),
        # An instance created before MetadataOptions existed reports nothing;
        # the effective behaviour of a missing HttpTokens is "optional".
        http_tokens=meta.get("HttpTokens", "optional"),
        http_endpoint=meta.get("HttpEndpoint", "enabled"),
        hop_limit=int(hop) if hop is not None else None,
        metadata_state=meta.get("State", "unknown"),
        has_role=bool(raw.get("IamInstanceProfile")),
        name=tags.get("Name"),
        template_id=tags.get(TEMPLATE_ID_TAG),
        template_version=tags.get(TEMPLATE_VERSION_TAG),
        asg_name=tags.get(ASG_TAG),
    )


def collect_instances(ec2, region: str, include_stopped: bool) -> List[Instance]:
    states = list(RUNNING_STATES)
    if include_stopped:
        states += STOPPED_STATES
    instances: List[Instance] = []
    paginator = ec2.get_paginator("describe_instances")
    pages = paginator.paginate(
        Filters=[{"Name": "instance-state-name", "Values": states}]
    )
    for page in pages:
        for reservation in page.get("Reservations", []):
            for raw in reservation.get("Instances", []):
                instances.append(_instance_from_api(raw, region))
    return instances


def collect_template_versions(ec2, region: str) -> List[TemplateVersion]:
    """The $Default and $Latest version of every launch template.

    Those two are the ones that can still mint new instances; older versions
    are history and reporting them would only add noise.
    """
    templates: List[Dict[str, Any]] = []
    paginator = ec2.get_paginator("describe_launch_templates")
    for page in paginator.paginate():
        templates.extend(page.get("LaunchTemplates", []))

    collected: List[TemplateVersion] = []
    for template in templates:
        template_id = template["LaunchTemplateId"]
        template_name = template.get("LaunchTemplateName", template_id)
        response = ec2.describe_launch_template_versions(
            LaunchTemplateId=template_id, Versions=["$Default", "$Latest"]
        )
        by_version: Dict[int, TemplateVersion] = {}
        for raw in response.get("LaunchTemplateVersions", []):
            number = int(raw["VersionNumber"])
            data = raw.get("LaunchTemplateData") or {}
            version = by_version.get(number)
            if version is None:
                version = TemplateVersion(
                    region=region,
                    template_id=template_id,
                    template_name=template_name,
                    version=number,
                    metadata_options=data.get("MetadataOptions"),
                )
                by_version[number] = version
            if raw.get("DefaultVersion") and "default" not in version.labels:
                version.labels.append("default")
            if number == int(template.get("LatestVersionNumber", number)):
                if "latest" not in version.labels:
                    version.labels.append("latest")
        collected.extend(by_version[k] for k in sorted(by_version))
    return collected


def collect_launch_configurations(autoscaling, region: str) -> List[LaunchConfiguration]:
    configs: List[LaunchConfiguration] = []
    paginator = autoscaling.get_paginator("describe_launch_configurations")
    for page in paginator.paginate():
        for raw in page.get("LaunchConfigurations", []):
            configs.append(
                LaunchConfiguration(
                    region=region,
                    name=raw["LaunchConfigurationName"],
                    metadata_options=raw.get("MetadataOptions"),
                )
            )
    return configs


def collect_region(
    ec2, autoscaling, region: str, include_stopped: bool = False
) -> RegionInventory:
    try:
        return RegionInventory(
            region=region,
            instances=collect_instances(ec2, region, include_stopped),
            template_versions=collect_template_versions(ec2, region),
            launch_configurations=collect_launch_configurations(autoscaling, region),
        )
    except ClientError as exc:
        code = (exc.response.get("Error") or {}).get("Code", "ClientError")
        message = (exc.response.get("Error") or {}).get("Message", str(exc))
        raise AwsAuditError(f"{region}: {code}: {message}") from exc
    except BotoCoreError as exc:
        raise AwsAuditError(f"{region}: {exc}") from exc


def resolve_region(session, explicit: Optional[List[str]]) -> List[str]:
    if explicit:
        return list(dict.fromkeys(explicit))
    region = getattr(session, "region_name", None)
    if not region:
        raise AwsAuditError(
            "no region configured: pass --region, or set AWS_REGION / a profile region"
        )
    return [region]
