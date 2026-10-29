import json

import pytest

from aws_ec2_imdsv2_audit.cli import build_parser, main


def test_clean_account_exits_zero(cli, capsys):
    assert cli(["--region", "eu-central-1"], "clean") == 0
    assert "No findings" in capsys.readouterr().out


def test_high_finding_exits_one(cli, capsys):
    assert cli(["--region", "eu-central-1"], "imdsv1-instance") == 1
    out = capsys.readouterr().out
    assert "IMDSV1_ENABLED" in out
    assert "modify-instance-metadata-options" in out


def test_fail_on_high_ignores_medium_only_account(cli, capsys):
    assert cli(["--region", "eu-central-1", "--fail-on", "high"], "hop-limit") == 0
    assert cli(["--region", "eu-central-1", "--fail-on", "medium"], "hop-limit") == 1
    assert "HOP_LIMIT_TOO_HIGH" in capsys.readouterr().out


def test_ignore_flag_changes_exit_code(cli):
    argv = ["--region", "eu-central-1", "--fail-on", "low", "--ignore"]
    assert cli(argv + ["METADATA_ENDPOINT_UNUSED"], "unused-endpoint") == 0


def test_json_output_is_valid_json(cli, capsys):
    cli(["--region", "eu-central-1", "--format", "json"], "mixed-account")
    payload = json.loads(capsys.readouterr().out)
    assert payload["scanned"]["instances"] == 4
    assert payload["scanned"]["launch_template_versions"] == 3
    assert payload["findings"][0]["severity"] == "high"


def test_csv_output_has_a_header(cli, capsys):
    cli(["--region", "eu-central-1", "--format", "csv"], "mixed-account")
    lines = capsys.readouterr().out.strip().splitlines()
    assert lines[0].startswith("severity,rule,region,resource_type")
    assert len(lines) > 1


def test_api_error_exits_two(cli, capsys):
    code = cli(
        ["--region", "eu-central-1"],
        "clean",
        error={"code": "RequestExpired", "message": "Request has expired."},
    )
    assert code == 2
    captured = capsys.readouterr()
    assert "RequestExpired" in captured.err
    assert "Traceback" not in captured.err


def test_missing_region_exits_two(capsys):
    class NoRegionSession:
        region_name = None

    code = main(
        [],
        client_factory=lambda region, profile: (None, None),
        session_factory=lambda profile: NoRegionSession(),
    )
    assert code == 2
    assert "no region configured" in capsys.readouterr().err


def test_unknown_ignore_rule_is_rejected():
    with pytest.raises(SystemExit) as excinfo:
        build_parser().parse_args(["--ignore", "NOT_A_RULE"])
    assert excinfo.value.code == 2
