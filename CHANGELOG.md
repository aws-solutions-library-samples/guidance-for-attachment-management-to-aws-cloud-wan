# Changelog

All notable changes to this Guidance are listed here. The version is in [`VERSION`](VERSION) and follows [semantic versioning](https://semver.org/) (see "Annex A — Development tooling" in the [README](README.md)).

Only the Terraform / OpenTofu modules have been deployed and tested end to end. The SAM / CloudFormation templates are provided on a best-effort basis, mirroring what is configured in the Terraform modules.

## 2.0.0 — 2026-11-16

### Attachment Manager
- Lambda organised into handler, AWS and local utilities, with structured decision log markers (`[TAG_ATTACHMENT=…]`, `[DISCONNECT_ATTACHMENT=…]`, `[RETRY_ATTACHMENT=…]`, `[SKIP_CONFLICT_CHECK=…]`).
- Conflict detection against region specific full return segments (`full_return_table_by_region` / `FullReturnTableByRegion`). Supports regions without last-hop loopbacks (regional inspection segments), mixed with regions that keep them, or with no global `fullreturn` segment at all.
- Valid attachments are tagged even without an IP address plan or a full return segment.
- Routes from Network Function Group attachments and segments (service insertion) are not evaluated.
- Attachments that are not ready are retried through SQS batch item failures (125 s visibility timeout, dead-letter queue after 5 deliveries, kept 14 days, with a CloudWatch alarm) instead of being re-queued forever.
- Ignored or non-listed accounts skip only their own attachment, not the other attachments propagating the same prefix.
- IPv6 prefixes (dual-stack VPCs) skip the IPv4 address plan check but are still checked for conflicting routes.
- Segment names restricted to letters and numbers (Terraform validation, SAM `AllowedPattern`, address map validation).
- Configurable route-domain tag, quarantine segments, account filtering and logging level.
- Terraform: the SNS subscription is created in `network_events_sns_topic_region`; the IP address plan file is generated per module instance; new `lambda_sqs_maximum_concurrency` (SAM `SqsMaximumConcurrency`) limits concurrency without throttling; removed the unneeded SQS invoke permission.

### Network Manager Events
- Events without a core network, deletions and route removals are dropped without failing the invocation; each route is forwarded once.
- Configured log level honoured.
- Lambda timeout 30 s; optional failure destination for events that still fail after the asynchronous retries (`lambda_destination_on_failure_arn` / `FailureDestinationArn`).
- Terraform `check` warning when not deployed in us-west-2.

### Infrastructure as code and tooling
- Terraform / OpenTofu modules for AWS provider v6, with OpenTofu tests (mocked providers) and plan snapshot tests whose AWS account IDs are masked automatically.
- SAM templates updated to Python 3.14 and to the Terraform module behaviour.
- CDKTF constructs removed.
- Lambda unit tests for both components (botocore Stubbers), including the regional inspection and IPv6 cases.
- pre-commit hooks (bandit, cfn-lint, gitleaks, shellcheck, OpenTofu format, solution ID, snapshot account IDs, semantic version) and the development tooling annex in the README.

## 1.0.0 — 2024-05-15

- Initial release: Network Manager events processor and Cloud WAN Attachment Manager (SAM / CloudFormation, Terraform and CDKTF).
