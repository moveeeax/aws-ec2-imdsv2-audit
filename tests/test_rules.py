import json

from aws_ec2_imdsv2_audit.collect import collect_region
from aws_ec2_imdsv2_audit.model import AwsAuditError
from aws_ec2_imdsv2_audit.report import render_csv, render_json, render_table
from aws_ec2_imdsv2_audit.rules import evaluate, exit_code

from conftest import load_fixture, stubbed_clients

REGION = "eu-central-1"


def inventory(name, include_stopped=False):
    with stubbed_clients(load_fixture(name), include_stopped=include_stopped) as (
        ec2,
        asg,
    ):
        return collect_region(ec2, asg, REGION, include_stopped)


def findings_for(name, ignore=()):
    return evaluate([inventory(name)], ignore)


def test_hardened_account_is_clean():
    findings = findings_for("clean")
    assert findings == []
    assert exit_code(findings, "low") == 0


def test_optional_tokens_instance_is_high_with_remediation():
    findings = findings_for("imdsv1-instance")
    rules = [f.rule for f in findings]
    assert "IMDSV1_ENABLED" in rules

    finding = next(f for f in findings if f.rule == "IMDSV1_ENABLED")
    assert finding.severity == "high"
    assert finding.resource_id == "i-0dead0beef0000001"
    assert finding.region == REGION
    assert "--http-tokens required" in finding.remediation
    assert "modify-instance-metadata-options" in finding.remediation
    assert "i-0dead0beef0000001" in finding.remediation
    assert "legacy-workers" in finding.detail


def test_template_without_metadata_options_is_reported_once_with_instance_count():
    findings = findings_for("template-no-metadata")
    template = [f for f in findings if f.rule == "TEMPLATE_IMDSV1"]
    assert len(template) == 1
    assert template[0].instance_count == 2
    assert template[0].resource_type == "launch-template-version"
    assert template[0].resource_id.startswith("lt-0legacy0000000001:2")
    assert "create-launch-template-version" in template[0].remediation
    # the two instances themselves are already hardened
    assert [f.rule for f in findings] == ["TEMPLATE_IMDSV1"]


def test_hop_limit_above_one_is_medium():
    findings = findings_for("hop-limit")
    assert [f.rule for f in findings] == ["HOP_LIMIT_TOO_HIGH"]
    assert findings[0].severity == "medium"
    assert "--http-put-response-hop-limit 1" in findings[0].remediation


def test_role_less_instance_with_metadata_on_is_low():
    findings = findings_for("unused-endpoint")
    assert [f.rule for f in findings] == ["METADATA_ENDPOINT_UNUSED"]
    assert findings[0].severity == "low"
    assert "--http-endpoint disabled" in findings[0].remediation


def test_fail_on_threshold_respects_severity():
    findings = findings_for("hop-limit")
    assert exit_code(findings, "high") == 0
    assert exit_code(findings, "medium") == 1
    assert exit_code(findings, "low") == 1
    assert exit_code(findings, "never") == 0


def test_ignore_drops_rule_from_output_and_exit_code():
    findings = findings_for("hop-limit", ignore=["HOP_LIMIT_TOO_HIGH"])
    assert findings == []
    assert exit_code(findings, "medium") == 0


def test_mixed_account_covers_every_rule_and_sorts_by_severity():
    inv = inventory("mixed-account")
    findings = evaluate([inv])
    rules = {f.rule for f in findings}
    assert rules == {
        "IMDSV1_ENABLED",
        "TEMPLATE_IMDSV1",
        "HOP_LIMIT_TOO_HIGH",
        "METADATA_ENDPOINT_UNUSED",
    }
    severities = [f.severity for f in findings]
    assert severities == sorted(
        severities, key=lambda s: -{"low": 1, "medium": 2, "high": 3}[s]
    )
    # the immutable launch configuration is flagged too
    assert any(f.resource_type == "launch-configuration" for f in findings)


def test_legacy_instance_without_metadata_options_counts_as_imdsv1():
    data = load_fixture("clean")
    data["instances"][0].pop("MetadataOptions")
    with stubbed_clients(data) as (ec2, asg):
        inv = collect_region(ec2, asg, REGION, False)
    assert [f.rule for f in evaluate([inv])] == ["IMDSV1_ENABLED"]


def test_disabled_endpoint_silences_instance_rules():
    data = load_fixture("imdsv1-instance")
    data["instances"][0]["MetadataOptions"]["HttpEndpoint"] = "disabled"
    with stubbed_clients(data) as (ec2, asg):
        inv = collect_region(ec2, asg, REGION, False)
    assert evaluate([inv]) == []


def test_stopped_instances_are_collected_only_with_the_flag():
    data = load_fixture("imdsv1-instance")
    data["instances"][0]["State"]["Name"] = "stopped"
    with stubbed_clients(data, include_stopped=True) as (ec2, asg):
        inv = collect_region(ec2, asg, REGION, True)
    assert len(inv.instances) == 1
    assert "state stopped" in evaluate([inv])[0].detail


def test_api_error_becomes_an_audit_error_not_a_traceback():
    with stubbed_clients(
        load_fixture("clean"),
        error={"code": "UnauthorizedOperation", "message": "not authorized"},
    ) as (ec2, asg):
        try:
            collect_region(ec2, asg, REGION, False)
        except AwsAuditError as exc:
            assert "UnauthorizedOperation" in str(exc)
            assert REGION in str(exc)
        else:  # pragma: no cover
            raise AssertionError("expected AwsAuditError")


def test_renderers_round_trip():
    inv = inventory("mixed-account")
    findings = evaluate([inv])

    table = render_table(findings, [inv])
    assert "SEVERITY" in table and "Remediation" in table
    assert "i-0dead0beef0000001" in table

    payload = json.loads(render_json(findings, [inv]))
    assert payload["summary"]["high"] >= 1
    assert payload["scanned"]["regions"] == [REGION]
    assert len(payload["findings"]) == len(findings)

    csv_text = render_csv(findings)
    assert csv_text.splitlines()[0].startswith("severity,rule,region")
    assert len(csv_text.splitlines()) == len(findings) + 1


def test_clean_table_says_so():
    inv = inventory("clean")
    assert "No findings" in render_table([], [inv])
