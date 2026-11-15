# Cloud WAN Attachment Manager — Terraform / OpenTofu module

A Terraform / OpenTofu module that enforces the segment membership of AWS Cloud WAN VPC attachments. Curated AWS Network Manager events (published by the [Network Manager Events](../../network-manager-events/terraform/) module) are delivered through SNS and SQS to a Lambda function that validates each VPC attachment propagating routes into the core network. It checks the account's `route-domain` AWS Organizations tag, the propagated CIDRs against the IP address plan, and the routes already present in the network. Then it either tags the attachment to its segment, moves it to quarantine, or deletes it.

## Architecture

```
Network Manager event (curated)
        │
        ▼
 SNS topic (Network Manager Events, us-west-2)
        │  filter: coreUplinkArn
        ▼
  SQS queue (main)  ──redrive──▶  SQS DLQ ──▶ CloudWatch alarm
        │  5 deliveries, 125 s visibility
        ▼
  Lambda function
  (Python 3.14, 90 s)
        │
        ├─── AWS Organizations (cross-account role)
        │    reads the `route-domain` account tag
        │
        ├─── Network Manager API
        │    checks conflicting routes in the full return segment
        │    (global, or per region when the last-hop loopback is removed)
        │
        └─── Decision
             ├── Valid     → tag attachment → user segment
             ├── Invalid   → delete (or quarantine if deletions are disabled)
             └── Not ready → reported back to SQS, retried after the visibility timeout
```

### Timing relationships

| Setting | Value | Reason |
|---------|-------|--------|
| Lambda execution | 90 s | Covers slow Cloud WAN API responses |
| SQS visibility | 125 s | Must exceed the Lambda timeout to prevent duplicate processing; also the back-off between retries of attachments that are not ready |
| SQS max receive count | 5 | Deliveries before the event moves to the DLQ |

### Service insertion and last-hop loopback removal

* Routes learned from Network Function Group attachments, or installed in Network Function Group segments (service insertion), are not evaluated.
* By default, conflicting routes are looked up in `full_return_table`, a segment that learns every attachment route (e.g. the return segment of last-hop loopback VPCs).
* When the last-hop loopback is removed for a region, its regional inspection segment learns that region's attachment routes instead. Use `full_return_table_by_region` (e.g. `{ "eu-west-1" = "inspectioneuw1" }`) to point the conflict detection to it. Regions not listed keep using `full_return_table`, so regions with and without loopbacks can be mixed.

### Files

| File | What it creates |
|------|----------------|
| `lambda.tf` | Lambda function (packaged from `../lambda/attachment_manager`) + SQS event source mapping + invoke permission |
| `sqs.tf` | Main SQS queue (125 s visibility) + dead-letter queue + queue policy |
| `sns.tf` | SNS subscription filtered to a specific core network ARN |
| `iam.tf` | Lambda execution policy (Network Manager, SQS, STS) and SQS queue policy |
| `cloudwatch.tf` | Dead-letter queue alarm |
| `data.tf` | Current region + caller identity data sources |
| `outputs.tf` | Queue URLs/ARNs, Lambda ARN, SNS subscription ARN, env-var mirrors |

## Usage

### Minimal — no IP plan validation, no conflict detection

```hcl
module "cloudwan_attachment_manager" {
  source = "./source/attachment-manager/terraform"

  providers = {
    aws                   = aws
    aws.aws_sns_subscribe = aws.network_events_region
  }

  name                            = "cloudwan-prod"
  aws_account_reader_role_arn     = "arn:aws:iam::000000000000:role/org-reader"
  global_network_id               = "global-network-0a1b2c3d4e5f6a7b8"
  core_network_arn                = "arn:aws:networkmanager::111111111111:core-network/core-network-0123456789abcdef0"
  network_events_sns_topic_region = "us-west-2"
  network_events_sns_topic_arn    = "arn:aws:sns:us-west-2:111111111111:networkmanager_events_global"
}
```

### Full — IP plan validation, conflict detection, loopback removal and account filtering

```hcl
module "cloudwan_attachment_manager" {
  source = "./source/attachment-manager/terraform"

  providers = {
    aws                   = aws
    aws.aws_sns_subscribe = aws.network_events_region
  }

  name                              = "cloudwan-prod"
  aws_account_reader_role_arn       = "arn:aws:iam::000000000000:role/org-reader"
  global_network_id                 = "global-network-0a1b2c3d4e5f6a7b8"
  core_network_arn                  = "arn:aws:networkmanager::111111111111:core-network/core-network-0123456789abcdef0"
  network_events_sns_topic_region   = "us-west-2"
  network_events_sns_topic_arn      = "arn:aws:sns:us-west-2:111111111111:networkmanager_events_global"
  cloudwatch_logs_retention_in_days = 30

  # Conflict detection: eu-west-2 still uses last-hop loopbacks (fullreturn),
  # eu-west-1 had its loopback removed (regional inspection segment)
  full_return_table           = "fullreturn"
  full_return_table_by_region = { "eu-west-1" = "inspectioneuw1" }

  # IP address plan: segment → region → accepted summaries
  vpc_segment_address_map = {
    prod    = { "eu-west-1" = ["10.0.0.0/16"], "eu-west-2" = ["10.1.0.0/16"] }
    nonprod = { "eu-west-1" = ["10.2.0.0/16"], "eu-west-2" = ["10.3.0.0/16"] }
  }

  # Quarantine rather than delete during initial roll-out
  lambda_perform_attachment_deletion = false
  lambda_logging_level               = "INFO"

  # Phased roll-out: only process a subset of accounts
  process_only_aws_accounts = ["222222222222", "333333333333"]
}
```

### Promoting a pre-built package across environments

```hcl
# Capture the built package path from the first environment:
# package_path = module.cloudwan_attachment_manager_dev.lambda_routing_config_local_package

module "cloudwan_attachment_manager_prod" {
  source = "./source/attachment-manager/terraform"
  # ...
  lambda_routing_config_local_package = var.package_path
}
```

## Providers

| Name | Version | Alias | Purpose |
|------|---------|-------|---------|
| `aws` | `~> 6.0` | — | Lambda, SQS, IAM resources in the Lambda region |
| `aws` | `~> 6.0` | `aws_sns_subscribe` | SNS subscription in the Network Manager events region |
| `local` | `~> 2.0` | — | Writes `vpc_segment_address_map.yml` into the Lambda package |

The `aws.aws_sns_subscribe` alias must be configured for the region where the Network Manager events SNS topic lives (`us-west-2`).

## Requirements

| Name | Version |
|------|---------|
| OpenTofu / Terraform | `>= 1.8` |
| AWS provider | `~> 6.0` |

## Inputs

### Required

| Name | Type | Description |
|------|------|-------------|
| `name` | `string` | Base name for all resources (SQS queues, Lambda function). |
| `aws_account_reader_role_arn` | `string` | Cross-account role ARN the Lambda assumes to read `route-domain` org tags. |
| `global_network_id` | `string` | Network Manager global network ID; required for Network Manager API calls. |
| `network_events_sns_topic_region` | `string` | Region where the network-events SNS topic lives. |
| `network_events_sns_topic_arn` | `string` | ARN of the SNS topic publishing curated Network Manager events. |

### Optional — Cloud WAN

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `core_network_arn` | `string` | `null` | Core network ARN; filters SNS events to this network only. When null, all events are forwarded. |
| `full_return_table` | `string` | `""` | Segment queried for conflicting CIDRs. Empty string disables conflict detection for regions not listed in `full_return_table_by_region`. |
| `full_return_table_by_region` | `map(string)` | `{}` | Region → segment queried for conflicting CIDRs, taking precedence over `full_return_table` (e.g. `{ "eu-west-1" = "inspectioneuw1" }`). |
| `vpc_segment_address_map` | `map(any)` | `null` | Segment → region → CIDR list. When set, propagated VPC CIDRs are validated before acceptance. |
| `cloudwan_route_domain_tag` | `string` | `"route-domain"` | Account / attachment tag holding the segment name. |
| `cloudwan_quarantine_table` | `string` | `"quarantine"` | Quarantine segment. |
| `cloudwan_quarantineroutes_table` | `string` | `"quarantineroutes"` | Segment learning the quarantined attachments routes. |

Segment names must only contain letters and numbers.

### Optional — Lambda behaviour

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `lambda_perform_attachment_deletion` | `bool` | `true` | When false, non-compliant attachments are quarantined instead of deleted. |
| `lambda_logging_level` | `string` | `"WARN"` | Logging verbosity: `WARN`, `INFO`, or `DEBUG`. |
| `lambda_runtime` | `string` | `"python3.14"` | Python runtime identifier. |
| `lambda_routing_config_local_package` | `string` | `null` | Pre-built `.zip` path; skips source packaging when set. |
| `lambda_reserved_concurrent_executions` | `number` | `null` | Maximum concurrent executions (e.g. `1` for sequential processing). |
| `cloudwatch_logs_retention_in_days` | `number` | `30` | Days to retain Lambda CloudWatch logs. |

### Optional — Account filtering

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `ignore_aws_accounts` | `list(string)` | `[]` | Account IDs to silently ignore. Takes precedence over `process_only_aws_accounts`. |
| `process_only_aws_accounts` | `list(string)` | `[]` | Allowlist of account IDs to process. All others are skipped when non-empty. |

### Optional — Infrastructure

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `region` | `string` | `null` | Override the AWS region for SQS and Lambda. Defaults to the provider's configured region. |
| `region_sns_topic_subscription` | `string` | `null` | Region for the aliased SNS subscription provider. |
| `sqs_delay_seconds` | `number` | `0` | Initial delay before SQS messages become visible (e.g. `15` for a redundant secondary deployment). |
| `dlq_alarm_enabled` | `bool` | `true` | Create a CloudWatch alarm on the dead-letter queue. |
| `dlq_alarm_sns_topic_arn` | `string` | `null` | SNS topic notified by the DLQ alarm. |
| `dlq_alarm_threshold` | `number` | `1` | Messages in the DLQ that trigger the alarm. |

## Outputs

| Name | Description |
|------|-------------|
| `lambda_function_name` | Name of the Lambda function (`{name}_{region}_routing`). |
| `lambda_function_arn` | ARN of the Lambda function. |
| `lambda_routing_config_local_package` | Local path to the built `.zip` (for environment promotion). |
| `sqs_queue_name` / `sqs_queue_arn` / `sqs_queue_url` | Main SQS queue. |
| `sqs_queue_visibility_timeout_seconds` | SQS visibility timeout (125 s). |
| `sqs_queue_delay_seconds` | SQS message delay. |
| `sqs_dlq_name` / `sqs_dlq_arn` | Dead-letter queue. |
| `sqs_max_receive_count` | Max deliveries before DLQ (5). |
| `sns_subscription_arn` | ARN of the SNS-to-SQS subscription. |
| `sns_filter_policy` | JSON filter policy restricting events to the managed core network (null when not set). |
| `dlq_alarm_arn` | ARN of the DLQ alarm, or null if disabled. |

## Lambda decision log markers

Search CloudWatch Logs for these markers to audit attachment decisions:

| Marker | Meaning |
|--------|---------|
| `[TAG_ATTACHMENT=USER_SEGMENT <id>]` | Accepted — tagged to its segment |
| `[TAG_ATTACHMENT=QUARANTINE_SEGMENT <id>]` | Invalid — moved to quarantine segment (deletions disabled) |
| `[DISCONNECT_ATTACHMENT=ABSENT_ACCOUNT_TAG <id>]` | No `route-domain` tag on the attachment or the account |
| `[DISCONNECT_ATTACHMENT=WRONG_ADDRESS_RANGE <id>]` | Propagated CIDR not in the IP address plan of the segment / region |
| `[DISCONNECT_ATTACHMENT=CONFLICTING_ROUTES <id>]` | Conflicting route detected in the full return segment |
| `[RETRY_ATTACHMENT=NOT_READY <id>]` | Attachment still pending; handed back to SQS for retry |

## Running tests

### HCL tests (OpenTofu mock providers, no AWS credentials needed)

```bash
cd source/attachment-manager/terraform
tofu init -backend=false
tofu test -test-directory=tests
```

### Lambda unit tests (pytest)

```bash
cd source/attachment-manager
pip install -r requirements-dev.txt
pytest
# run a single test by name:
pytest -k "test_process_route_event_new_route_ok"
```

### Plan snapshot tests (require AWS credentials for `tofu plan`)

```bash
cd source/attachment-manager/terraform
pytest -m terraform
pytest -m terraform --snapshot-update   # after intentional changes
```
