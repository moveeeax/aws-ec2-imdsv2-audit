"""Stubbed EC2 / Auto Scaling clients built from the recorded JSON fixtures."""

from __future__ import annotations

import json
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

import boto3
import pytest
from botocore.stub import Stubber

FIXTURES = Path(__file__).resolve().parents[1] / "examples" / "fixtures"
REGION = "eu-central-1"


def load_fixture(name: str) -> Dict[str, Any]:
    return json.loads((FIXTURES / f"{name}.json").read_text())


def _session():
    return boto3.Session(
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
        aws_session_token="testing",
        region_name=REGION,
    )


def _state_values(include_stopped: bool) -> List[str]:
    return ["running", "stopped", "stopping"] if include_stopped else ["running"]


@contextmanager
def stubbed_clients(
    data: Dict[str, Any],
    region: str = REGION,
    include_stopped: bool = False,
    error: Optional[Dict[str, str]] = None,
):
    """Queue exactly the calls collect_region() makes, in order."""
    session = _session()
    ec2 = session.client("ec2", region_name=region)
    autoscaling = session.client("autoscaling", region_name=region)

    with Stubber(ec2) as ec2_stub, Stubber(autoscaling) as asg_stub:
        instance_params = {
            "Filters": [
                {"Name": "instance-state-name", "Values": _state_values(include_stopped)}
            ]
        }
        if error:
            ec2_stub.add_client_error(
                "describe_instances",
                service_error_code=error["code"],
                service_message=error["message"],
                http_status_code=error.get("status", 403),
                expected_params=instance_params,
            )
            yield ec2, autoscaling
            return

        ec2_stub.add_response(
            "describe_instances",
            {"Reservations": [{"Instances": data["instances"]}]},
            instance_params,
        )
        ec2_stub.add_response(
            "describe_launch_templates",
            {"LaunchTemplates": data["launch_templates"]},
            {},
        )
        for template in data["launch_templates"]:
            template_id = template["LaunchTemplateId"]
            ec2_stub.add_response(
                "describe_launch_template_versions",
                {
                    "LaunchTemplateVersions": data["launch_template_versions"][
                        template_id
                    ]
                },
                {"LaunchTemplateId": template_id, "Versions": ["$Default", "$Latest"]},
            )
        asg_stub.add_response(
            "describe_launch_configurations",
            {"LaunchConfigurations": data["launch_configurations"]},
            {},
        )
        yield ec2, autoscaling


def run_cli(argv, fixture_name: str, error: Optional[Dict[str, str]] = None):
    """Run the CLI end to end against a fixture; returns (exit_code, stdout_capture)."""
    from aws_ec2_imdsv2_audit.cli import main

    data = load_fixture(fixture_name) if fixture_name else {
        "instances": [],
        "launch_templates": [],
        "launch_template_versions": {},
        "launch_configurations": [],
    }
    include_stopped = "--include-stopped" in argv

    with stubbed_clients(data, include_stopped=include_stopped, error=error) as clients:
        def client_factory(region, profile):
            return clients

        def session_factory(profile):
            return _session()

        return main(
            list(argv),
            client_factory=client_factory,
            session_factory=session_factory,
        )


@pytest.fixture
def cli():
    return run_cli
