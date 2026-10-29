#!/usr/bin/env python3
"""Run the audit offline against examples/fixtures/mixed-account.json.

No AWS account, no credentials: botocore's Stubber answers the three API calls
from the recorded fixture. Handy for seeing the output shape before you point
the tool at a real account.

    python3 examples/demo.py            # table
    python3 examples/demo.py --format json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import boto3
from botocore.stub import Stubber

from aws_ec2_imdsv2_audit.cli import main

REGION = "eu-central-1"
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "mixed-account.json"


def build_stubbed_clients(data):
    session = boto3.Session(
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
        region_name=REGION,
    )
    ec2 = session.client("ec2")
    autoscaling = session.client("autoscaling")

    ec2_stub = Stubber(ec2)
    ec2_stub.add_response(
        "describe_instances",
        {"Reservations": [{"Instances": data["instances"]}]},
        {"Filters": [{"Name": "instance-state-name", "Values": ["running"]}]},
    )
    ec2_stub.add_response(
        "describe_launch_templates", {"LaunchTemplates": data["launch_templates"]}, {}
    )
    for template in data["launch_templates"]:
        template_id = template["LaunchTemplateId"]
        ec2_stub.add_response(
            "describe_launch_template_versions",
            {"LaunchTemplateVersions": data["launch_template_versions"][template_id]},
            {"LaunchTemplateId": template_id, "Versions": ["$Default", "$Latest"]},
        )
    ec2_stub.activate()

    asg_stub = Stubber(autoscaling)
    asg_stub.add_response(
        "describe_launch_configurations",
        {"LaunchConfigurations": data["launch_configurations"]},
        {},
    )
    asg_stub.activate()

    return ec2, autoscaling


if __name__ == "__main__":
    clients = build_stubbed_clients(json.loads(FIXTURE.read_text()))
    sys.exit(
        main(
            ["--region", REGION, *sys.argv[1:]],
            client_factory=lambda region, profile: clients,
            session_factory=lambda profile: None,
        )
    )
