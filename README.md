# aws-ec2-imdsv2-audit
Audits EC2 instances, launch templates and launch configurations for reachable IMDSv1. Flags HttpTokens=optional, templates that keep minting IMDSv1 instances, hop limits above 1, and unused metadata endpoints. Prints the remediation call and exits non-zero in CI.
