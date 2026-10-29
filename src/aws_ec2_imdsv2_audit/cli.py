"""Command line entry point."""

from __future__ import annotations

import argparse
import sys
from typing import Callable, List, Optional, Sequence, Tuple

from . import __version__
from .collect import collect_region, resolve_region
from .model import AwsAuditError, RegionInventory
from .report import render
from .rules import RULES, evaluate, exit_code

ClientFactory = Callable[[str, Optional[str]], Tuple[object, object]]


def _default_clients(region: str, profile: Optional[str]):
    import boto3

    session = boto3.Session(profile_name=profile, region_name=region)
    return session.client("ec2"), session.client("autoscaling")


def _default_session(profile: Optional[str]):
    import boto3

    return boto3.Session(profile_name=profile)


def _ignore_list(value: str) -> List[str]:
    rules = [item.strip().upper() for item in value.split(",") if item.strip()]
    unknown = [rule for rule in rules if rule not in RULES]
    if unknown:
        raise argparse.ArgumentTypeError(
            f"unknown rule(s): {', '.join(unknown)}. Known: {', '.join(sorted(RULES))}"
        )
    return rules


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aws-ec2-imdsv2-audit",
        description=(
            "Find EC2 instances, launch templates and launch configurations that "
            "still leave IMDSv1 reachable."
        ),
    )
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument(
        "--region",
        action="append",
        dest="regions",
        metavar="REGION",
        help="region to scan; repeatable. Defaults to the session region.",
    )
    parser.add_argument(
        "--format", choices=("table", "json", "csv"), default="table"
    )
    parser.add_argument(
        "--fail-on",
        choices=("high", "medium", "low", "never"),
        default="high",
        help="lowest severity that makes the exit code 1 (default: high)",
    )
    parser.add_argument(
        "--ignore",
        type=_ignore_list,
        default=[],
        metavar="RULE,RULE",
        help="rules to drop from the output and the exit code",
    )
    parser.add_argument(
        "--include-stopped",
        action="store_true",
        help="also audit stopped instances (they keep their metadata options)",
    )
    parser.add_argument("--version", action="version", version=__version__)
    return parser


def main(
    argv: Optional[Sequence[str]] = None,
    client_factory: ClientFactory = _default_clients,
    session_factory: Callable[[Optional[str]], object] = _default_session,
) -> int:
    args = build_parser().parse_args(argv)

    try:
        regions = resolve_region(session_factory(args.profile), args.regions)
        inventories: List[RegionInventory] = []
        for region in regions:
            ec2, autoscaling = client_factory(region, args.profile)
            inventories.append(
                collect_region(ec2, autoscaling, region, args.include_stopped)
            )
    except AwsAuditError as exc:
        print(f"aws-ec2-imdsv2-audit: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # credentials and client construction live here
        print(f"aws-ec2-imdsv2-audit: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    findings = evaluate(inventories, args.ignore)
    print(render(args.format, findings, inventories))
    return exit_code(findings, args.fail_on)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
