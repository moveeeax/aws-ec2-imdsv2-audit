# aws-ec2-imdsv2-audit

[![ci](https://github.com/moveeeax/aws-ec2-imdsv2-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/aws-ec2-imdsv2-audit/actions/workflows/ci.yml)
[![python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue)](https://www.python.org/)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Find the EC2 instances, launch templates and launch configurations in an AWS account that
still leave IMDSv1 reachable — and the launch templates that keep putting the hole back
after you fix the instances.

IMDSv1 is an unauthenticated `GET`. One SSRF in an app running on the box reads the
instance role credentials. Switching an instance to IMDSv2 does nothing on its own: it is
`HttpTokens=required` that closes IMDSv1, and `optional` means the instance answers both.

## Rules

| Rule | Severity | What it means |
| --- | --- | --- |
| `IMDSV1_ENABLED` | high | Instance has `HttpTokens=optional` (or no `MetadataOptions` at all), so it still answers IMDSv1. |
| `TEMPLATE_IMDSV1` | high | A launch template `$Default`/`$Latest` version, or a launch configuration, has no `MetadataOptions` or `HttpTokens=optional`. The next scale-out undoes your instance fixes. |
| `HOP_LIMIT_TOO_HIGH` | medium | `HttpPutResponseHopLimit > 1`, so containers on a bridge network can reach the node role. |
| `METADATA_ENDPOINT_UNUSED` | low | `HttpEndpoint=enabled` on an instance with no instance profile: nothing needs IMDS there. |

## How it works

Three API calls per region, joined locally:

- `DescribeInstances` → `MetadataOptions`, the attached instance profile, and the
  `aws:ec2launchtemplate:id` / `aws:autoscaling:groupName` tags AWS adds for you.
- `DescribeLaunchTemplateVersions` for `$Default` and `$Latest` of every launch template —
  the only two versions that can still mint new instances.
- `DescribeLaunchConfigurations` for the legacy ASG path, where the config is immutable and
  the fix is a migration to a launch template.

A template is reported **once**, with the number of collected instances launched from it,
instead of once per instance. Every finding carries the exact remediation call.

A missing `MetadataOptions` block is treated as IMDSv1-enabled, because that is how the
instance actually behaves.

## Install

```bash
pip install git+https://github.com/moveeeax/aws-ec2-imdsv2-audit.git
```

Needs read-only `ec2:DescribeInstances`, `ec2:DescribeLaunchTemplates`,
`ec2:DescribeLaunchTemplateVersions` and `autoscaling:DescribeLaunchConfigurations`.

## Usage

```bash
aws-ec2-imdsv2-audit --region eu-central-1
aws-ec2-imdsv2-audit --region eu-central-1 --region eu-west-1 --format json --fail-on high
aws-ec2-imdsv2-audit --include-stopped --ignore METADATA_ENDPOINT_UNUSED
```

```
$ aws-ec2-imdsv2-audit --region eu-central-1
Scanned 4 instance(s), 3 launch template version(s), 1 launch configuration(s) in eu-central-1

SEVERITY  RULE                      REGION        RESOURCE                                                 DETAIL
--------  ------------------------  ------------  -------------------------------------------------------  -----------------------------------------------
HIGH      IMDSV1_ENABLED            eu-central-1  i-0dead0beef0000001 (legacy-worker-01 / legacy-workers)  HttpTokens=optional: answers unauthenticated…
HIGH      TEMPLATE_IMDSV1           eu-central-1  lt-0legacy0000000001:2 (default) (batch-legacy)          no MetadataOptions block: every instance thi…
MEDIUM    HOP_LIMIT_TOO_HIGH        eu-central-1  lt-0legacy0000000001:3 (latest) (batch-legacy)           HttpPutResponseHopLimit=3: new instances sta…
LOW       METADATA_ENDPOINT_UNUSED  eu-central-1  i-0noro1e000000001a (bastion)                            HttpEndpoint=enabled with no instance profil…

Remediation
  IMDSV1_ENABLED i-0dead0beef0000001
    aws ec2 modify-instance-metadata-options --region eu-central-1 --instance-id i-0dead0beef0000001 --http-tokens required --http-endpoint enabled
  ...

Findings: 4 high, 2 medium, 1 low
```

Full captured output: [`examples/sample-report.txt`](examples/sample-report.txt),
[`examples/sample-report.json`](examples/sample-report.json),
[`examples/sample-report.csv`](examples/sample-report.csv).

### Flags

| Flag | Default | Notes |
| --- | --- | --- |
| `--profile` | session default | AWS profile name. |
| `--region` | session region | Repeatable; each region is scanned separately. |
| `--format` | `table` | `table`, `json` or `csv`. |
| `--fail-on` | `high` | Lowest severity that makes the exit code `1`. `never` always exits `0`. |
| `--ignore` | — | Comma-separated rule names; dropped from output **and** exit code. |
| `--include-stopped` | off | Stopped instances keep their metadata options, so they matter at next start. |

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No finding at or above `--fail-on`. |
| `1` | At least one finding at or above `--fail-on`. |
| `2` | AWS API error, missing credentials, no region, or a bad flag. |

## In CI

```yaml
- name: IMDSv2 audit
  run: aws-ec2-imdsv2-audit --region eu-central-1 --fail-on high
```

## Try it without an AWS account

`examples/demo.py` runs the whole audit against a recorded fixture using botocore's
`Stubber`, so it needs no credentials:

```bash
pip install -e '.[dev]'
python examples/demo.py
python examples/demo.py --format json
```

## Tests

```bash
pip install -e '.[dev]'
pytest -q
```

23 tests, all offline: every rule, both exit-code thresholds, `--ignore`, the three
output formats, a legacy instance with no `MetadataOptions`, and a denied API call that
must exit `2` rather than print a traceback.

## License

MIT
