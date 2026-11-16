# Cloud WAN Attachment Manager — Terraform / OpenTofu module

A Terraform module that automatically enforces routing policies on AWS Cloud WAN VPC attachments. When a VPC attaches to a Cloud WAN core network, an SNS event triggers a Lambda function that validates the attachment — checking the account's `route-domain` organisation tag, the VPC's CIDR range, and existing routes — then either tags the attachment to the correct segment, moves it to quarantine, or deletes it.

The events come from the [Network Manager Events](../../network-manager-events/terraform/) module, deployed once in us-west-2. The same component can also be deployed with SAM (`../cloudformation/template.yml`), which mirrors this module on a best-effort basis: only the Terraform modules have been deployed and tested end to end.

## Architecture

```
CloudWAN attachment event
        │
        ▼
 AWS Network Manager
 SNS topic (us-west-2)
        │  filter: coreUplinkArn
        ▼
  SQS queue (main)  ──redrive──▶  SQS DLQ  ──▶  CloudWatch alarm
        │  5 retries, 125 s visibility
        ▼
  Lambda function
  (Python 3.14, 90 s)
        │
        ├─── AWS Organizations (cross-account)
        │    reads `route-domain` account tag
        │
        ├─── NetworkManager API
        │    checks overlapping routes in full-return segment
        │    (global, or per region without last-hop loopbacks)
        │
        └─── Decision
             ├── Valid  → tag attachment → user segment
             ├── Invalid → delete (or quarantine if deletions disabled)
             └── Not ready → batch item failure for SQS retry
```

### Timing relationships

| Timeout | Value | Reason |
|---------|-------|--------|
| Lambda execution | 90 s | Covers slow Cloud WAN API responses |
| SQS visibility | 125 s | Must exceed Lambda timeout to prevent duplicate processing; back-off before retrying an attachment that is not ready |
| SQS max retries | 5 | Deliveries before moving to DLQ |

### Service insertion and loopback removal

| Scenario | Behaviour |
|----------|-----------|
| Network Function Group attachments / segments | Learned routes are not evaluated (service insertion) |
| Regions with last-hop loopbacks | Overlapping routes are checked in `full_return_table` (e.g. `fullreturn`) |
| Regions without last-hop loopbacks | Overlapping routes are checked in the regional segment set in `full_return_table_by_region` (e.g. `{"eu-west-1" = "inspectioneuw1"}`) |
| No loopback in any region | `full_return_table = ""` and one `full_return_table_by_region` entry per region. A region missing from the map is admitted without the overlap check, logged as `[SKIP_CONFLICT_CHECK=NO_FULL_RETURN_SEGMENT <id>]` |
| Dual-stack VPCs (IPv6 prefixes) | The IP address plan only covers IPv4, so IPv6 prefixes skip it. They are still checked for overlapping routes |

Limitations of regional inspection segments as full return segments, to verify on the core network policy:
- The check only queries `PROPAGATED` routes at the attachment's edge. If an inspection segment only learns other regions' summaries, overlaps with VPCs in other regions are not detected.
- If quarantined routes are shared into the inspection segments, a re-fired route event of an admitted VPC can match an overlapping newcomer that is still in quarantine, and the admitted VPC is deleted too.

### Files

| File | What it creates |
|------|----------------|
| `lambda.tf` | Lambda function (Python 3.14, 90 s, packaged from `../lambda/attachment_manager`) + SQS event source mapping + per-instance address map file |
| `sqs.tf` | Main SQS queue (125 s visibility) + dead-letter queue (14-day retention) + queue policy |
| `sns.tf` | SNS subscription filtered to a specific core network ARN |
| `iam.tf` | Lambda execution role with NetworkManager, SQS, STS |
| `cloudwatch.tf` | CloudWatch alarm on the dead-letter queue |
| `data.tf` | Current region + caller identity data sources |
| `outputs.tf` | Queue URLs/ARNs, Lambda ARN, SNS subscription ARN, env-var mirrors |

## Prerequisite: SCP denying the `route-domain` tag

The attachment manager only works if tenants can't pick their own segment. [`source/scp-cloudwan-attachment-tagging.json`](../../scp-cloudwan-attachment-tagging.json) is an example Service Control Policy. It denies `networkmanager:CreateVpcAttachment`, `UpdateVpcAttachment` and `TagResource` whenever the request carries the `route-domain` tag key (`aws:TagKeys`):

```json
{
  "Effect": "Deny",
  "Action": [
    "networkmanager:UpdateVpcAttachment",
    "networkmanager:TagResource",
    "networkmanager:CreateVpcAttachment"
  ],
  "Resource": "arn:aws:networkmanager:*",
  "Condition": { "ForAnyValue:StringEquals": { "aws:TagKeys": "route-domain" } }
}
```

Why it matters: without it, a tenant could create or tag an attachment with `route-domain=<any segment>`. The core network policy would then place the attachment straight into that segment, bypassing the quarantine, the IP plan check and the overlap check.

When applying it:
- **Attach it to the tenant OUs / accounts only**, never to the network account where this Lambda runs and tags attachments.
- **Keep the tag key aligned** with `cloudwan_route_domain_tag` (default `route-domain`) and with the attachment policies of the core network policy.
- **`UntagResource` is not denied.** A tenant removing the tag from its own attachment only sends it back to `quarantine` (the core network policy fallback). The route events that follow make the Lambda re-evaluate it from the account tag and re-admit it after the same checks. That can't grant access to another segment.

---

## Lambda execution flow

The Lambda is the only component that decides whether a VPC can reach the rest of the network. User accounts can't choose their segment (the [SCP](#prerequisite-scp-denying-the-route-domain-tag) denies the `route-domain` tag), so every new attachment lands in `quarantine` and stays isolated until the Lambda admits it. Admission is therefore **fail-closed**: an event that is dropped, fails, or is never retried leaves the VPC in quarantine rather than wrongly connected.

### 1. SQS batch (`handler`)

```
 SQS batch (up to 10 messages)
   │
   ├─ read env once: global network, FULL_RETURN_TABLE(_BY_REGION), address map,
   │                 account lists, PERFORM_ATTACHMENT_DELETIONS
   │
   └─ for each message ──▶ SNS envelope? ──no──▶ ignore (unhandled, deleted from queue)
                              │yes
                              ▼
                     Cloud WAN event? (changeType, edgeRegion,
                      coreNetworkArn, apiChangeType) ──no──▶ ignore
                              │yes
                              ▼
                     process_cloudwan_event
                              │
            ┌─────────────────┼──────────────────────────┐
            ▼                 ▼                          ▼
          done          retry needed               exception
     (message deleted)  (attachment not ready)     (API error, bad data)
                              │                          │
                              └──────────┬───────────────┘
                                         ▼
                           batchItemFailures += messageId
                                         │
                  visible again after 125 s ── 5th delivery ──▶ DLQ ──▶ alarm
```

Why it matters: only the failed messages of a batch are retried (`ReportBatchItemFailures`), and every retry is a real SQS redelivery. The visibility timeout (125 s) is the back-off, the redrive policy caps retries at 5, and anything left over is visible in the DLQ and its alarm instead of looping forever. The Lambda timeout (90 s) must stay below the visibility timeout, or a message could be processed twice at the same time.

### 2. Event filtering (`process_cloudwan_event`)

```
 changeType == "new_route" and routes + segments present? ──no──▶ ignore ("set" events)
   │yes
   ▼
 route installed in a Network Function Group segment? ──yes──▶ ignore (service insertion)
   │no
   ▼
 full return segment for edgeRegion:
     FULL_RETURN_TABLE_BY_REGION[edge]  ──▶ else FULL_RETURN_TABLE ──▶ else none (check skipped)
   │
   ▼
 for each route ──▶ process_route_event (VPC attachments only)
```

Why it matters: decisions are taken on `SEGMENT_ROUTE_INSTALLED`, when the VPC's CIDRs are actually known to the core network, not on attachment creation. The segment queried for overlaps depends on the region. Regions with a last-hop loopback use `fullreturn`; regions without one use their inspection segment. When neither is set, the overlap check is skipped and logged.

### 3. Attachment decision (`process_route_event`)

```
 for each VPC attachment of the route
   │
   ├─ Network Function Group attachment? ─────────────────────────▶ skip
   ├─ account ignored / not in allow-list? ───────────────────────▶ skip (next attachment)
   │
   ├─ state UPDATING / PENDING_* ─────────────────────────────────▶ retry (batch item failure)
   ├─ state other than AVAILABLE ─────────────────────────────────▶ unhandled
   │
   └─ AVAILABLE
        │
        ▼
      segment = attachment route-domain tag
                └─ else AWS Organizations account tag (assumed reader role)
        │
        ├─ no tag at all ─────────────────────────────────────────▶ DELETE
        │
        ├─ 1. IP plan: prefix inside segment/region ranges?
        │      (skipped: no map, segment not in map, IPv6 prefix)
        │      no ────────────────────────────────────────────────▶ DELETE
        │
        ├─ 2. overlaps: supernet + subnet PROPAGATED routes from
        │      other VPCs in <full return segment> and quarantineroutes
        │      (skipped when no full return segment: SKIP_CONFLICT_CHECK)
        │      found ─────────────────────────────────────────────▶ DELETE
        │
        └─ 3. not yet tagged to its segment ──────────────────────▶ TAG route-domain=<segment>

 DELETE ──▶ PERFORM_ATTACHMENT_DELETIONS=true  ──▶ delete_attachment
        └─▶ PERFORM_ATTACHMENT_DELETIONS=false ──▶ tag route-domain=quarantine
```

Why it matters:
- **The order of the checks is the security model.** A VPC is only tagged into a business segment after its address range has been checked against the plan, and against what the network already routes. An overlapping VPC would otherwise blackhole or hijack traffic of an existing workload.
- **`quarantineroutes` closes the race between newcomers.** Two overlapping VPCs that are both still in quarantine see each other there, so neither is admitted.
- **The attachment tag wins over the account tag.** Once admitted, a later route event for the same attachment is a no-op, and re-checks skip `quarantineroutes` so the admitted VPC isn't penalised by a newcomer.
- **Quarantine instead of delete** (`lambda_perform_attachment_deletion = false`) keeps the decision visible and reversible during roll-out. The same `[DISCONNECT_ATTACHMENT=…]` markers are logged.
- **Account filters skip one attachment, not the route.** Other attachments propagating the same prefix are still evaluated.

---

## Usage

### Minimal — no IP validation, no conflict detection

```hcl
module "cloudwan" {
  source = "./source/attachment-manager/terraform"

  providers = {
    aws                   = aws
    aws.aws_sns_subscribe = aws.network_events_region
  }

  name                            = "cloudwan-prod"
  aws_account_reader_role_arn     = "arn:aws:iam::000000000000:role/org-reader"
  global_network_id               = "global-network-0a1b2c3d4e5f6a7b8"
  network_events_sns_topic_region = "us-west-2"
  network_events_sns_topic_arn    = "arn:aws:sns:us-west-2:111111111111:network_manager_events"
}
```

### Full — with IP validation, conflict detection, loopback removal, and account filtering

```hcl
module "cloudwan" {
  source = "./source/attachment-manager/terraform"

  providers = {
    aws                   = aws
    aws.aws_sns_subscribe = aws.network_events_region
  }

  name                              = "cloudwan-prod"
  aws_account_reader_role_arn       = "arn:aws:iam::000000000000:role/org-reader"
  global_network_id                 = "global-network-0a1b2c3d4e5f6a7b8"
  core_network_arn                  = "arn:aws:networkmanager:us-east-1:111111111111:core-network/c0123456789abcdef"
  network_events_sns_topic_region   = "us-west-2"
  network_events_sns_topic_arn      = "arn:aws:sns:us-west-2:111111111111:network_manager_events"
  cloudwatch_logs_retention_in_days = 30

  # eu-west-2 keeps its last-hop loopback, eu-west-1 had it removed
  full_return_table           = "fullreturn"
  full_return_table_by_region = {
    "eu-west-1" = "inspectioneuw1"
  }

  vpc_segment_address_map = {
    prod    = { "eu-west-1" = ["10.0.0.0/16"], "eu-west-2" = ["10.1.0.0/16"] }
    nonprod = { "eu-west-1" = ["10.2.0.0/16"], "eu-west-2" = ["10.3.0.0/16"] }
  }

  # Quarantine rather than delete during initial roll-out
  lambda_perform_attachment_deletion = false
  lambda_logging_level               = "INFO"

  # Phased roll-out: only process a subset of accounts
  process_only_aws_accounts = ["123456789012", "234567890123"]
}
```

### Regional inspection only — no `fullreturn` segment

Every region had its last-hop loopback removed, so there is no global full return segment. Each region's inspection segment is queried for overlapping routes instead.

```hcl
module "cloudwan" {
  source = "./source/attachment-manager/terraform"

  providers = {
    aws                   = aws
    aws.aws_sns_subscribe = aws.network_events_region
  }

  name                            = "cloudwan-prod"
  aws_account_reader_role_arn     = "arn:aws:iam::000000000000:role/org-reader"
  global_network_id               = "global-network-0a1b2c3d4e5f6a7b8"
  core_network_arn                = "arn:aws:networkmanager:us-east-1:111111111111:core-network/c0123456789abcdef"
  network_events_sns_topic_region = "us-west-2"
  network_events_sns_topic_arn    = "arn:aws:sns:us-west-2:111111111111:network_manager_events"

  full_return_table = ""
  full_return_table_by_region = {
    "eu-west-1" = "inspectioneuw1"
    "eu-west-2" = "inspectioneuw2"
  }

  # Close to sequential processing without throttling the function
  lambda_sqs_maximum_concurrency = 2
}
```

### Several instances (primary and secondary region)

Each instance writes its address map to `builds/<name>_<region>_address_map/` under the root module, so instances never share or delete each other's file (see [Lambda packaging and the IP address plan](#lambda-packaging-and-the-ip-address-plan)). The secondary instance usually sets `sqs_delay_seconds = 15`.

### Promoting a pre-built package across environments

```hcl
# Capture the built package path from the first environment:
# package_path = module.cloudwan_dev.lambda_routing_config_local_package

module "cloudwan_prod" {
  source = "./source/attachment-manager/terraform"
  # ...
  lambda_routing_config_local_package = var.package_path
}
```

## Lambda packaging and the IP address plan

The IP address plan isn't read from S3 or SSM at runtime. Terraform generates it from `vpc_segment_address_map` and bundles it into the Lambda package before the build, so every package version carries the plan it was deployed with.

```
 var.vpc_segment_address_map (HCL map)
   │  yamlencode()
   ▼
 local_file.vpc_segment_address_map
   ${path.root}/builds/<name>_<region>_address_map/vpc_segment_address_map.yml
   │
   │  depends_on: the packager (data.external.archive_prepare) waits until
   │  apply whenever the file must be created or changed, so the package
   │  hash always includes the current map
   ▼
 terraform-aws-modules/lambda build (source_path list)
   ├─ ${path.module}/../lambda/attachment_manager  pip_requirements = true
   │     pip install -r requirements.txt (boto3, pyyaml) + handler code
   └─ builds/<name>_<region>_address_map/       (only when the map is set)
         │
         ▼
 zip root (/var/task at runtime)
   lambda_handler.py · aws_utils.py · local_utils.py · yaml/ · boto3/ · …
   vpc_segment_address_map.yml  ◀── SEGMENT_ADDRESSING_FILE = "vpc_segment_address_map.yml"
```

Why it matters:
- **One directory per instance.** The file is written outside the module source, under `builds/<name>_<region>_address_map/`, next to the zips the Lambda module already writes to `builds/`. A primary and a secondary instance never overwrite each other's map, and destroying one never removes the other's file. If the file were missing from a package, `SEGMENT_ADDRESSING_FILE` would point to nothing, every message would fail, and the messages would end up in the DLQ.
- **`pip_requirements = true` is required.** With a list of paths the packager doesn't detect `requirements.txt` by itself, unlike a single string path. Without the flag, `pyyaml` (not part of the Lambda runtime) would be missing and the handler would fail on import. No test catches its removal: the synthesis snapshot only records the references of a computed `source_path` (`path.module`, `local.address_map_dir`, …), not its value, and the HCL tests can't see module inputs. Keep the comment in `lambda.tf` next to it.
- **Fresh checkouts and CI runners.** `builds/` isn't committed. When the file is missing, `local_file` plans to recreate it, so the build waits for it again and bundles it.
- **No map, no file.** With `vpc_segment_address_map = null`, no file is written, only the code directory is packaged, `SEGMENT_ADDRESSING_FILE` is empty and the IP plan check is skipped.
- **Changing the plan means redeploying the Lambda.** A change to `vpc_segment_address_map` changes the package hash and publishes new code. With `lambda_routing_config_local_package` (promoting a pre-built zip), the map bundled in that zip is used.
- **Validation happens twice.** Terraform rejects segment names that aren't letters and numbers, and `local_utils` validates the structure and the CIDRs when the file is loaded. A malformed plan fails the invocation, and the messages are retried and then sent to the DLQ.

---

## Providers

| Name | Version | Alias | Purpose |
|------|---------|-------|---------|
| `aws` | `~> 6.0` | — | Lambda, SQS, IAM resources in the Lambda region |
| `aws` | `~> 6.0` | `aws_sns_subscribe` | SNS subscription in the Network Manager event region |
| `local` | `~> 2.0` | — | Writes `vpc_segment_address_map.yml`, bundled into the Lambda package |

The `external` and `null` providers are required by the `terraform-aws-modules/lambda` module (package build), not by this module directly.

The subscription is created in `network_events_sns_topic_region` whatever the region of the `aws.aws_sns_subscribe` provider. Use the alias for a different account or credentials; for the same account, pass `aws`.

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
| `global_network_id` | `string` | Network Manager global network ID; required for NetworkManager API calls. |
| `network_events_sns_topic_region` | `string` | Region where the network-events SNS topic lives (us-west-2). The SNS subscription is created there. |
| `network_events_sns_topic_arn` | `string` | ARN of the SNS topic publishing Cloud WAN attachment events. |

### Optional — Cloud WAN

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `core_network_arn` | `string` | `null` | Core network ARN; filters SNS events to this network only. When null, no filter policy is set and all events are forwarded. |
| `full_return_table` | `string` | `""` | Routing segment queried for overlapping CIDRs. Empty string disables conflict detection (except for regions in `full_return_table_by_region`). |
| `full_return_table_by_region` | `map(string)` | `{}` | Map of region → segment queried for overlapping CIDRs, taking precedence over `full_return_table` (e.g. `{"eu-west-1" = "inspectioneuw1"}` when the last-hop loopback is removed). |
| `vpc_segment_address_map` | `map(any)` | `null` | Map of segment → region → CIDR list. When set, VPC CIDRs are validated before acceptance. |
| `cloudwan_route_domain_tag` | `string` | `"route-domain"` | AWS Organizations account tag holding the segment of the account. |
| `cloudwan_quarantine_table` | `string` | `"quarantine"` | Segment isolating non-compliant attachments. |
| `cloudwan_quarantineroutes_table` | `string` | `"quarantineroutes"` | Segment learning the routes of quarantined attachments. |

Segment names (including the keys of `vpc_segment_address_map`) must only contain letters and numbers.

### Optional — Lambda behaviour

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `lambda_perform_attachment_deletion` | `bool` | `true` | When false, non-compliant attachments are quarantined instead of deleted. |
| `lambda_logging_level` | `string` | `"WARN"` | Logging verbosity: `WARN`, `INFO`, or `DEBUG`. |
| `lambda_runtime` | `string` | `"python3.14"` | Python runtime identifier. |
| `lambda_routing_config_local_package` | `string` | `null` | Pre-built `.zip` path; skips source packaging when set. |
| `lambda_reserved_concurrent_executions` | `number` | `null` | Reserved concurrency of the function. Don't use it to limit SQS processing: throttled receives count towards the DLQ redrive. |
| `lambda_sqs_maximum_concurrency` | `number` | `null` | Maximum concurrency of the SQS event source mapping (2-1000). `2` keeps processing close to sequential without throttling. |
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
| `region_sns_topic_subscription` | `string` | `null` | Region of the SNS subscription. Defaults to `network_events_sns_topic_region`. |
| `sqs_delay_seconds` | `number` | `0` | Initial delay before SQS messages become visible to consumers. |
| `dlq_alarm_enabled` | `bool` | `true` | Create a CloudWatch alarm for messages arriving in the DLQ. |
| `dlq_alarm_sns_topic_arn` | `string` | `null` | SNS topic notified by the DLQ alarm. |
| `dlq_alarm_threshold` | `number` | `1` | Number of DLQ messages that triggers the alarm. |

## Outputs

| Name | Description |
|------|-------------|
| `lambda_function_name` | Name of the Lambda function (`{name}_{region}_routing`). |
| `lambda_function_arn` | ARN of the Lambda function. |
| `lambda_routing_config_local_package` | Local path to the built `.zip` (for environment promotion). |
| `sqs_queue_name` | Name of the main SQS queue. |
| `sqs_queue_arn` | ARN of the main SQS queue. |
| `sqs_queue_url` | URL of the main SQS queue. |
| `sqs_queue_visibility_timeout_seconds` | SQS visibility timeout (125 s). |
| `sqs_queue_delay_seconds` | SQS message delay. |
| `sqs_dlq_name` | Name of the dead-letter queue. |
| `sqs_dlq_arn` | ARN of the dead-letter queue. |
| `sqs_max_receive_count` | Max deliveries before DLQ (5). |
| `sns_subscription_arn` | ARN of the SNS-to-SQS subscription. |
| `sns_subscription_region` | Region in which the SNS subscription is created. |
| `lambda_env_full_return_table` | Value of `FULL_RETURN_TABLE` (empty when only regional segments are used). |
| `lambda_env_full_return_table_by_region` | JSON value of `FULL_RETURN_TABLE_BY_REGION`. |
| `sns_filter_policy` | JSON filter policy restricting events to the managed core network (null when `core_network_arn` is not set). |
| `dlq_alarm_arn` | ARN of the DLQ CloudWatch alarm, or null if disabled. |

## Lambda decision log markers

Search CloudWatch Logs for these markers to audit attachment decisions:

| Marker | Meaning |
|--------|---------|
| `[TAG_ATTACHMENT=USER_SEGMENT <id>]` | Accepted — tagged to the user segment |
| `[TAG_ATTACHMENT=QUARANTINE_SEGMENT <id>]` | Invalid — moved to quarantine segment |
| `[DISCONNECT_ATTACHMENT=ABSENT_ACCOUNT_TAG <id>]` | No `route-domain` org tag on the account |
| `[DISCONNECT_ATTACHMENT=WRONG_ADDRESS_RANGE <id>]` | VPC CIDR not in expected range |
| `[DISCONNECT_ATTACHMENT=CONFLICTING_ROUTES <id>]` | Overlapping route detected in full-return table |
| `[RETRY_ATTACHMENT=NOT_READY <id>]` | Attachment still pending; handed back to SQS for retry |
| `[SKIP_CONFLICT_CHECK=NO_FULL_RETURN_SEGMENT <id>]` | (WARN) No full return segment for the attachment region: admitted without the overlap check |

## Running tests

The repository-wide tooling (pre-commit, bandit, cfn-lint, snapshot masking) is described in the main README, "Annex A — Development tooling".

### HCL tests (OpenTofu mock framework, no credentials)

```bash
cd source/attachment-manager/terraform
tofu init -backend=false
tofu test -test-directory=tests
```

The tests use `mock_provider` blocks, so they need no credentials and create nothing. Every run is `command = plan`.
- **Deployment tests** (`test_full_deployment`, `test_minimal_deployment`, `test_regional_inspection_deployment`) mock `aws`, its `aws_sns_subscribe` alias, and also `external`, `null` and `local`. The last three serve the `terraform-aws-modules/lambda` packaging: `data.external.archive_prepare` runs `package.py` to hash the sources, `null_resource.archive` builds the zip, and `local_file` writes the address map. Mocking them stops `tofu test` from running any of it.
- **`test_validation_failure`** mocks `aws` only. Its negative runs fail at variable validation, before anything is planned. Its positive runs plan with the real `external` provider, which only hashes the sources (needs `python3`); the build itself only runs at apply.
- **No HCL test sets `vpc_segment_address_map`:** `yamlencode()` of a `map(any)` hits an OpenTofu 1.11.5 mock-value bug. The address map is covered by the Lambda unit tests, and by the `test_module` instance of the snapshot tests.

Covers:
- **`test_full_deployment`** — SQS naming, visibility timeout, redrive policy, SNS filter and full-return tables with all inputs provided
- **`test_minimal_deployment`** — null/empty code paths with only required inputs; verifies no SNS filter is set and SQS is created without optional features
- **`test_regional_inspection_deployment`** — regional inspection segments without a `fullreturn` segment; SNS subscription region, SQS event source mapping concurrency, DLQ retention
- **`test_validation_failure`** — variable validation: logging levels, log retention, SQS delay, SQS maximum concurrency, name, role ARN, and segment names (letters and numbers only)

### Lambda unit tests (pytest)

```bash
cd source/attachment-manager
pip install -r requirements-dev.txt
pytest
# run a single test by name:
pytest tests/test_routing_config.py -k "test_function_name"
# IPv6 (dual-stack VPC) cases:
pytest tests/test_ipv6.py
```

### Plan snapshot tests (pytest, requires AWS credentials)

```bash
cd source/attachment-manager/terraform
pytest -m terraform
pytest -m terraform --snapshot-update   # after intentional changes
```

The snapshot tests run a real `tofu plan` of `tests/test_snapshot.tf` (with `tests/test_provider_snapshot.tf`). They compare the generated configuration (`test_synthesizes_properly.json`) and the planned values (`test_planned_values.json`) with the JSON files committed in `tests/__snapshots__/`, so any change in what the module would deploy shows up as a reviewable diff. Volatile attributes (file names, content, timestamps, triggers) are excluded from the comparison.

`tests/test_snapshot.tf` plans two instances: `test_module` (global `fullreturn`, address map) and `test_module_regional` (regional inspection segments only, no `fullreturn`). Review snapshot diffs carefully: unexpected changes in planned values indicate unintended drift.

`tofu plan` resolves `data.aws_caller_identity` with the credentials in use. The snapshot tests mask every non-mock account ID (as `111111111111`) before comparing or writing the snapshots (`deployment/snapshot_account_ids.py`), and the `snapshot-account-ids` pre-commit hook rejects any snapshot that still contains one. This repository must never contain real AWS account IDs.

How the snapshot tests work: [terraform-snapshot-test on GitHub](https://github.com/joaorodrig/terraform-snapshot-test), [on PyPI](https://pypi.org/project/terraform-snapshot-test/), and the blog post [Terraform snapshot testing: a practical guide](https://empirikon.co.uk/blog/terraform-snapshot-testing-a-practical/).
