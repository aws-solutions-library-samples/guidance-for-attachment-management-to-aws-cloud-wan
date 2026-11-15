# Network Manager Events — Terraform / OpenTofu module

> An opinionated Terraform / OpenTofu module that wires AWS Network Manager
> into an event-driven pipeline, turning raw topology changes into structured,
> filterable SNS messages — without any custom infrastructure plumbing.

---

## Overview

When AWS Network Manager detects a change in your cloud WAN — a VPC attachment
coming online, a segment route being propagated, an attachment going away — it
emits a raw event to Amazon EventBridge. Out of the box those events contain
enough information to know *something* changed, but not enough to act on it
efficiently: subscribers must deserialise every message to figure out whether
it is relevant to them.

This module solves that. It deploys a lightweight processing pipeline that
intercepts Network Manager events, enriches them with SNS message attributes
(`changeType`, `attachmentRegion`, `coreNetworkArn`, …), and publishes the
result to an encrypted SNS topic. Downstream consumers — SQS queues, Lambda
functions, HTTP endpoints — can then subscribe with attribute-based filter
policies and receive *only* the events they care about.

---

## Architecture

```
 ┌──────────────────────────────────────────────────────────────────────┐
 │  AWS Network Manager                                                 │
 │                                                                      │
 │  ┌─────────────────────────────────────────────────────────────────┐ │
 │  │  Global Network  (Core Network + VPC / TGW / SD-WAN attachments)│ │
 │  └────────────────────────────┬────────────────────────────────────┘ │
 │                               │ topology change event                │
 └───────────────────────────────┼──────────────────────────────────────┘
                                 │
                                 ▼
 ┌──────────────────────────────────────────────────────────────────────┐
 │  Amazon EventBridge                                                  │
 │  rule: source = ["aws.networkmanager"]                               │
 │  bus:  default  (or custom, via var.events_bus_name)                 │
 └────────────────────────────────┬─────────────────────────────────────┘
                                  │
                                  ▼
 ┌──────────────────────────────────────────────────────────────────────┐
 │  AWS Lambda  —  network_events_sns_publish_<name>                    │
 │                                                                      │
 │  Processes:                                                          │
 │    VPC_ATTACHMENT_CREATED  →  changeType = "set"                     │
 │    SEGMENT_ROUTE_INSTALLED →  changeType = "new_route"               │
 │    *_DELETED / *_UNINSTALLED → silently dropped                      │
 │                                                                      │
 │  Adds SNS message attributes:                                        │
 │    coreNetworkArn · changeType · attachmentRegion                    │
 │    coreUplinkArn  · attachmentArn (when present)                     │
 └────────────────────────────────┬─────────────────────────────────────┘
                                  │
                                  ▼
 ┌──────────────────────────────────────────────────────────────────────┐
 │  Amazon SNS  —  networkmanager_events_<name>                         │
 │  (KMS-encrypted · standard topic)                                    │
 └──────┬──────────────────────┬─────────────────────────────┬──────────┘
        │                      │                             │
        ▼                      ▼                             ▼
  SQS queue             Lambda function               HTTP endpoint
  (filter by            (filter by                    (webhooks, etc.)
   attachmentRegion)     changeType=new_route)
```

---

## Important: Enable Network Manager Event Monitoring

> **This is a manual step that Terraform cannot perform for you.**

After the module is applied, you must enable event monitoring on the core
network attached to the Global Network. Without this, Network Manager will not
emit events to EventBridge and the pipeline will never fire.

Enable via the AWS Console → Network Manager → Global Networks → *your network*
→ **Event settings** → turn on event monitoring.

Or via CLI:
```
aws networkmanager update-network-resource-metadata \
  --global-network-id <id> --metadata enable_monitoring=true
```

Reference: https://docs.aws.amazon.com/vpc/latest/tgwnm/monitoring-events.html

---

## Usage

AWS Network Manager publishes its events to Amazon EventBridge in **us-west-2**, so the module must be deployed in that region.

```hcl
module "network_manager" {
  source = "./source/network-manager-events/terraform"

  # Required
  global_network_name               = "prod-core-network"
  cloudwatch_logs_retention_in_days = 14

  # Optional overrides
  lambda_logging_level = "WARN"   # WARN | INFO | DEBUG
}

# Subscribe an SQS queue, filtering to attachment events only
resource "aws_sns_topic_subscription" "attachments" {
  topic_arn = module.network_manager.sns_topic_arn
  protocol  = "sqs"
  endpoint  = aws_sqs_queue.attachments.arn

  filter_policy = jsonencode({
    changeType = ["VPC_ATTACHMENT_CREATED"]
  })
}
```

### Multi-account / custom event bus

```hcl
module "network_manager" {
  source = "..."

  global_network_name               = "prod-core-network"
  cloudwatch_logs_retention_in_days = 14
  events_bus_name                   = "network-manager-forwarded-events"
}
```

---

## SNS Message Format

The Lambda publishes a JSON message body alongside SNS message attributes.

**Message body** (`Message` field):

```json
{
  "changeType":     "set",
  "coreNetworkArn": "arn:aws:networkmanager::123456789012:core-network/core-network-abc",
  "coreNetworkId":  "core-network-abc",
  "apiChangeType":  "VPC_ATTACHMENT_CREATED",
  "edgeRegion":     "eu-west-1",
  "attachmentArn":  "arn:aws:networkmanager::123456789012:attachment/attachment-xyz",
  "attachmentId":   "attachment-xyz",
  "routes":         [],
  "segments":       [],
  "coreUplinkArn":  "arn:aws:networkmanager::..."
}
```

**Message attributes** (usable as SNS filter policy keys):

| Attribute         | Type   | Present when                         |
|-------------------|--------|--------------------------------------|
| `coreNetworkArn`  | String | Always                               |
| `changeType`      | String | Always (raw API value)               |
| `attachmentRegion`| String | Always                               |
| `coreUplinkArn`   | String | Always                               |
| `attachmentArn`   | String | Attachment events only               |

**Processed `changeType` values** (in message body):

| `apiChangeType`              | Body `changeType` |
|------------------------------|-------------------|
| `*_ATTACHMENT_CREATED`       | `set`             |
| `*_PEERING_CREATED`          | `set`             |
| `*_CONNECTION_CREATED`       | `set`             |
| `SEGMENT_ROUTE_INSTALLED`    | `new_route`       |
| `*_DELETED` / `*_UNINSTALLED`| *(dropped)*       |

---

## Requirements

| Name | Version |
|------|---------|
| terraform / opentofu | >= 1.7 |
| aws | ~> 6.0 |

---

## Providers

| Name | Version |
|------|---------|
| aws | ~> 6.0 |

---

## Modules

| Name | Source | Version |
|------|--------|---------|
| `lambda_network_events_sns_publish` | [terraform-aws-modules/lambda/aws](https://registry.terraform.io/modules/terraform-aws-modules/lambda/aws/latest) | 8.8.0 |

---

## Resources

| Name | Type |
|------|------|
| `aws_networkmanager_global_network.global_network` | resource |
| `aws_cloudwatch_event_rule.network_manager_events` | resource |
| `aws_cloudwatch_event_target.network_manager_events` | resource |
| `aws_lambda_permission.network_manager_events` | resource |
| `aws_sns_topic.network_manager_events` | resource |
| `aws_sns_topic_policy.network_manager_events` | resource |
| `data.aws_caller_identity.current` | data source |
| `data.aws_iam_policy_document.lambda_network_manager_events` | data source |
| `data.aws_iam_policy_document.sns_network_manager_events` | data source |
| `data.aws_region.current` | data source |

---

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| `global_network_name` | Human-readable name for the Global Network. Used as a suffix in all derived resource names. | `string` | — | **yes** |
| `cloudwatch_logs_retention_in_days` | Days to retain Lambda CloudWatch log events. Use `0` for indefinite. | `number` | `30` | no |
| `events_bus_name` | EventBridge bus the rule subscribes to. Override for cross-account event routing. | `string` | `"default"` | no |
| `lambda_logging_level` | Lambda logger verbosity. One of `WARN`, `INFO`, `DEBUG`. | `string` | `"WARN"` | no |
| `sns_topic_name` | Override the auto-generated SNS topic name (`networkmanager_events_<name>`). | `string` | `null` | no |
| `region` | AWS region for the Lambda function. Defaults to the provider region. | `string` | `null` | no |
| `lambda_runtime` | Python runtime identifier (e.g. `python3.14`). | `string` | `"python3.14"` | no |

---

## Outputs

| Name | Description |
|------|-------------|
| `global_network_id` | ID of the AWS Network Manager Global Network. |
| `sns_topic_arn` | ARN of the SNS topic that receives enriched Network Manager events. |
| `region_name` | AWS region in which the module's resources were deployed. |

---

## Development

```bash
# HCL tests — mocked provider, no AWS credentials required
cd source/network-manager-events/terraform
tofu init -backend=false
tofu test -test-directory=tests

# Plan snapshot tests — require AWS credentials for `tofu plan`
pytest -m terraform
pytest -m terraform --snapshot-update   # after an intentional infrastructure change

# Lambda unit tests
cd source/network-manager-events
pip install -r requirements-dev.txt
pytest
```

| Command | What it tests |
|---------|--------------|
| `tofu test -test-directory=tests` | HCL tests in `tests/module_tests.tftest.hcl` — resource wiring, naming conventions, security properties, variable validation. |
| `pytest -m terraform` (in `terraform/`) | Snapshot tests — run `tofu plan` and compare the plan JSON against the committed snapshots in `tests/__snapshots__/`. |
| `pytest` (in `source/network-manager-events`) | Python unit tests for the Lambda `_process_event()` function. |

Review snapshot diffs carefully before committing — unexpected changes in planned values indicate unintended drift, and snapshots must not contain real AWS account IDs.
