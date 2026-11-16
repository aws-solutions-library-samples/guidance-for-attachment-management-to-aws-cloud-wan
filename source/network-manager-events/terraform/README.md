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


The events are consumed by the [Cloud WAN Attachment Manager](../../attachment-manager/terraform/) module. The same component can also be deployed with SAM (`../cloudformation/template.yml`), which mirrors this module on a best-effort basis: only the Terraform modules have been deployed and tested end to end.

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

## Lambda execution flow

```
 EventBridge (us-west-2, source = aws.networkmanager)
   │  asynchronous invocation (Lambda retries twice, then the optional
   │  lambda_destination_on_failure_arn)
   ▼
 handler
   │
   ▼
 _process_event(event)
   │
   ├─ detail.changeType, coreNetworkArn or edgeLocation missing? ──▶ drop
   │      (global network / TGW / SD-WAN events without a core network)
   │
   ├─ *_ATTACHMENT_DELETED / *_PEERING_DELETED / *_CONNECTION_DELETED ──▶ drop
   │
   ├─ *_ATTACHMENT_CREATED / *_PEERING_CREATED / *_CONNECTION_CREATED
   │      ──▶ changeType = "set"        ──▶ publish
   │
   ├─ SEGMENT_ROUTE_INSTALLED
   │      keep routes with at least one typed attachment (once per route)
   │      no route left, or no segment? ─────────────────────────────▶ drop
   │      ──▶ changeType = "new_route"  ──▶ publish
   │
   └─ anything else (route removals, policy changes, …) ──────────────▶ drop

 publish = sns:Publish(compact JSON body + message attributes:
           coreNetworkArn · changeType · attachmentRegion · coreUplinkArn · attachmentArn)
```

Why it matters:
- **It is the only event source of the attachment manager.** Network Manager only publishes in us-west-2, and SNS fans the events out to attachment managers in any region (cross-region SQS subscriptions). If this Lambda drops an event, the attachment stays in quarantine. That fails closed, so the only cost is a delayed admission, which the next route event usually recovers.
- **Message attributes let subscribers filter without a Lambda.** Each attachment manager subscribes with an SNS filter policy on `coreUplinkArn`, so a topic shared by several core networks only delivers each network's events to its own queue.
- **Curating at the source keeps consumers simple and cheap.** Deletions, removals and untyped routes are dropped here. Each route appears once in the message even when several attachments propagate it, so consumers don't process duplicates. The JSON body carries only what the attachment manager needs: `edgeRegion`, `routes`, `segments`.
- **Unknown or partial events never fail the invocation.** Missing fields return `None` instead of raising, so EventBridge/Lambda don't retry events that can never be processed. Real failures, such as an SNS publish error, raise and are retried twice, then go to the failure destination when one is set.

---

## Important: Deploy in us-west-2

Network Manager is a global service whose home region is **us-west-2**: it only
publishes its EventBridge events there. Deploy this module in us-west-2 (provider
region or `region = "us-west-2"`). Anywhere else the EventBridge rule never
fires; the `network_manager_events_region` check block reports it as a warning
at plan time.

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
| `region` | AWS region for the resources. Must resolve to `us-west-2` (Network Manager events region). Defaults to the provider region. | `string` | `null` | no |
| `lambda_destination_on_failure_arn` | SQS queue, SNS topic, Lambda or event bus receiving events that still fail after 2 asynchronous retries. When null, failures only appear in the Lambda logs / `Errors` metric. | `string` | `null` | no |
| `lambda_runtime` | Python runtime identifier (e.g. `python3.13`, `python3.14`). | `string` | `"python3.14"` | no |

---

## Outputs

| Name | Description |
|------|-------------|
| `global_network_id` | ID of the AWS Network Manager Global Network. |
| `sns_topic_arn` | ARN of the SNS topic that receives enriched Network Manager events. |
| `region_name` | AWS region in which the module's resources were deployed. |
| `lambda_timeout` | Timeout of the publisher Lambda function (30 s). |
| `lambda_destination_on_failure_arn` | Destination of failed asynchronous invocations, or null. |

---

## Development

The repository-wide tooling (pre-commit, bandit, cfn-lint, snapshot masking) is described in the main README, "Annex A — Development tooling".

### Commands

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

# Type-check the Lambda handler (boto3 ships no type stubs)
MYPYPATH=lambda/sns_publish_attributes mypy --ignore-missing-imports -p lambda_handler
```

### Test structure

| Command | What it tests |
|---------|--------------|
| `tofu test -test-directory=tests` (in `terraform/`) | HCL tests in `tests/module_tests.tftest.hcl` — resource wiring, naming conventions, security properties, variable validation, the us-west-2 check, Lambda timeout and failure destination. Uses a mocked AWS provider; no credentials needed. |
| `pytest -m terraform` (in `terraform/`) | Snapshot tests — run `tofu plan` and compare the plan JSON against the committed snapshots in `tests/__snapshots__/`. |
| `pytest` (in `source/network-manager-events`) | Python unit tests for the Lambda `_process_event()` function — covers all event type branches and edge cases (including events without a core network). |

### HCL test mocks

The tests mock the `aws` provider only (`mock_provider "aws"`), so they need no credentials and create nothing. The `external` and `null` providers come from the `terraform-aws-modules/lambda` module's packaging and are not mocked:
- `data.external.archive_prepare` really runs `package.py` at plan time, which only hashes the Lambda sources and writes a build plan under `builds/` (needs `python3`);
- `null_resource.archive`, which builds the zip, only runs at apply, and every run is `command = plan`.

The mocked `aws_region` returns us-west-2. The `warn_when_not_deployed_in_us_west_2` run overrides it to eu-west-1 and expects the `network_manager_events_region` check to fail.

### Snapshots

The snapshot tests run a real `tofu plan` of `tests/test_snapshot.tf` (with `tests/test_provider_snapshot.tf`). They compare the generated configuration (`test_synthesizes_properly.json`) and the planned values (`test_planned_values.json`) with the JSON files committed in `tests/__snapshots__/`, so any change in what the module would deploy shows up as a reviewable diff. Volatile attributes (file names, content, timestamps, triggers) are excluded from the comparison. The snapshot configuration uses an eu-west-1 provider, so its plan shows the `network_manager_events_region` warning. Snapshot files in `tests/__snapshots__/` must be committed alongside infrastructure changes; review the diff carefully, since unexpected changes in planned values indicate unintended drift.

`tofu plan` resolves `data.aws_caller_identity` with the credentials in use. The snapshot tests mask every non-mock account ID (as `111111111111`) before comparing or writing the snapshots (`deployment/snapshot_account_ids.py`), and the `snapshot-account-ids` pre-commit hook rejects any snapshot that still contains one. This repository must never contain real AWS account IDs.

How the snapshot tests work: [terraform-snapshot-test on GitHub](https://github.com/joaorodrig/terraform-snapshot-test), [on PyPI](https://pypi.org/project/terraform-snapshot-test/), and the blog post [Terraform snapshot testing: a practical guide](https://empirikon.co.uk/blog/terraform-snapshot-testing-a-practical/).
