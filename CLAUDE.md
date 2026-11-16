# CLAUDE.md

This file guides [Claude Code](https://claude.com/claude-code) when it works on this repository. The 2.0.0 update of this Guidance was developed with Claude Code's assistance, reviewed by the maintainer (see "Authors" in `README.md`). Commits made with it carry a `Co-Authored-By: Claude` trailer.

## What this is

An AWS Solutions Guidance (solution ID **SO9490**) that automates the admission of VPC attachments into AWS Cloud WAN segments. User accounts cannot pick their own segment: new attachments go to a `quarantine` segment. A Lambda in the network account later tags each attachment with `route-domain=<segment>`. It takes the segment from the owning account's AWS Organizations tag, then checks the VPC's propagated CIDRs against an optional IP plan and against routes already in the network. If a check fails, the Lambda deletes the attachment, or re-tags it to `quarantine` when deletions are disabled.

The CI workflow (`.github/workflows/maintainer_workflows.yml`, managed by the aws-solutions-library-samples maintainers) only greps the repository for the solution ID. Keep `SO9490` in the SAM template descriptions (the `solution-id` pre-commit hook checks it). Don't modify the maintainer-managed files: `.github/`, `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, `LICENSE`, `CODEOWNERS`.

## Architecture (event flow)

There are two independently deployed components under `source/`. Each has a Lambda in `lambda/`, a SAM template in `cloudformation/` (the deployment path the README documents) and a Terraform / OpenTofu module in `terraform/`. Only the Terraform modules have been deployed and tested end to end. The SAM templates mirror them on a best-effort basis, so when you change infrastructure behaviour (env vars, IAM, queue settings, SNS filter, timeouts), change both.

1. **`network-manager-events`**: deploy once, in **us-west-2** (Network Manager only publishes its EventBridge events there; the Terraform `check` block warns otherwise). The EventBridge rule `source: aws.networkmanager` triggers `lambda/sns_publish_attributes`, which curates the event:
   - attachment created becomes `changeType` = `set`;
   - `SEGMENT_ROUTE_INSTALLED` becomes `new_route`, keeping only routes with typed attachments, each route once.

   It publishes to SNS with message attributes, including `coreUplinkArn`, and drops deletions and events without a core network. The Lambda timeout is 30 s, with an optional failure destination.
2. **`attachment-manager`**: deploy in one or more regions; a redundant secondary uses an SQS delay of 15 s. SQS is subscribed cross-region to the topic, filtered on `coreUplinkArn`: visibility timeout 125 s, DLQ after 5 deliveries kept 14 days, DLQ alarm, optional event source mapping maximum concurrency. It feeds `lambda/attachment_manager` (`lambda_handler.py`, `aws_utils.py`, `local_utils.py`).

Key behaviour of the attachment manager:
- Only `new_route` events do work. Routes from Network Function Group attachments or segments (service insertion) are skipped.
- Ignored / non-listed accounts skip their own attachment only (`continue`), never the other attachments of the route.
- The segment comes from the attachment's `route-domain` tag; if absent, from the account's AWS Organizations tag, read via the assumed `AWS_ACCOUNT_READ_ROLE_ARN`. With no tag at all, the attachment is deleted.
- Checks run in order:
  1. The IP address plan (`vpc_segment_address_map.yml`). Skipped when the map isn't set, the segment isn't in it, or the prefix is IPv6 (the plan is IPv4 only).
  2. Conflicting routes (supernet and subnet `get_network_routes`, `PROPAGATED`), checked in the full return segment plus `quarantineroutes`. The full return segment is `FULL_RETURN_TABLE_BY_REGION[edge]`, falling back to `FULL_RETURN_TABLE`. That's how regions without last-hop loopbacks point at their `inspection<abbr>` segment, with or without a global `fullreturn`. When both are empty the check is skipped and logged as `[SKIP_CONFLICT_CHECK=NO_FULL_RETURN_SEGMENT …]`.
  3. Tagging to the segment.
- A failed check deletes the attachment, or tags it `quarantine` when `PERFORM_ATTACHMENT_DELETIONS=false`.
- Attachments in `UPDATING` / `PENDING_*` are returned as `batchItemFailures`. SQS redelivers them after the visibility timeout, so the Lambda timeout (90 s) and the visibility timeout (125 s) are coupled.
- Segment names (inputs and address-map keys) must be letters and numbers only. This is validated in Terraform, SAM `AllowedPattern` and `local_utils`.
- Decision log markers: `[TAG_ATTACHMENT=…]`, `[DISCONNECT_ATTACHMENT=…]`, `[RETRY_ATTACHMENT=NOT_READY …]`, `[SKIP_CONFLICT_CHECK=…]`.

IP address plan packaging:
- **SAM:** copy `cloudformation/vpc_segment_address_map.yml` into `lambda/attachment_manager/` (gitignored) before `sam build`; `{}` disables the IP plan check.
- **Terraform:** `local_file` writes the map per module instance to `${path.root}/builds/<name>_<region>_address_map/`, added as a second `source_path` entry. The first entry needs `pip_requirements = true`, or pyyaml isn't packaged.

## Commands

```sh
# All development tooling
pip install -r requirements.txt

# Lambda unit tests (pytest.ini sets pythonpath and env; AWS calls are botocore Stubbers)
cd source/attachment-manager && pytest
pytest -k test_process_route_event_new_route_ok        # single test
pytest tests/test_ipv6.py                              # IPv6 cases
cd source/network-manager-events && pytest

# Terraform module tests (mocked providers, no credentials)
cd source/<component>/terraform && tofu init -backend=false && tofu test -test-directory=tests

# Plan snapshot tests (need AWS credentials: `tofu plan` reads data.aws_caller_identity)
cd source/<component>/terraform && pytest -m terraform [--snapshot-update]

# Repository checks (README "Annex A — Development tooling")
pre-commit run --all-files
bandit -c bandit.yml -r source deployment
cfn-lint source/*/cloudformation/template.yml
```

Snapshots must never contain real AWS account IDs. Both `test_terraform_snapshot.py` files mask the plan with `mask_account_ids()` from `deployment/snapshot_account_ids.py` (it becomes `111111111111`) before comparing or writing, and the `snapshot-account-ids` pre-commit hook rejects unmasked snapshots. Use mock IDs (`000000000000`, `111111111111`, …, `123456789012`) everywhere else too.

The version is in `VERSION` (semver). Bump it together with `CHANGELOG.md`.

## Deployment prerequisites (outside this repository)

These are described in `README.md`:
- the core network policy (with `quarantine` / `quarantineroutes` segments, and attachment policies on the `route-domain` tag falling back to `quarantine`);
- the SCP denying the `route-domain` tag to user accounts (`source/scp-cloudwan-attachment-tagging.json`);
- the management-account role allowing `organizations:Describe*` / `List*`;
- accounts tagged with `route-domain` at account vending.
