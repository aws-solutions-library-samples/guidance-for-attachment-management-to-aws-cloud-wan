# ─────────────────────────────────────────────────────────────────────────────
# HCL Tests — aws-network-manager module
# ─────────────────────────────────────────────────────────────────────────────
#
# These tests use OpenTofu's native test framework with a fully mocked AWS
# provider. No real AWS credentials or deployed infrastructure are required.
#
# Run with:
#   tofu init -backend=false
#   tofu test
#
# (The snapshot-based pytest tests are separate:
#   tofu test -test-directory=tests)
#
# Test inventory
# ──────────────
# POSITIVE
#   default_naming_conventions              Resource names embed global_network_name
#   custom_sns_topic_name_overrides_default var.sns_topic_name takes precedence
#   default_events_bus_is_account_default   events_bus_name defaults to "default"
#   custom_events_bus_applied_to_rule       Custom bus name propagates to rule
#   sns_topic_security_properties           KMS encryption, non-FIFO, no dedup
#   eventbridge_rule_filters_network_manager_only  Pattern source = aws.networkmanager
#   eventbridge_lambda_invocation_chain     Rule → Target → Permission wiring
#   lambda_permission_scoped_to_rule        source_arn restricts invoker to this rule
#   module_outputs_wired_correctly          Outputs map to correct data sources
#
# NEGATIVE
#   reject_unrecognised_logging_level       "VERBOSE" fails var validation
#   reject_standard_python_log_level        "ERROR" fails var validation

# ─────────────────────────────────────────────────────────────────────────────
# Mock provider
# ─────────────────────────────────────────────────────────────────────────────
#
# A single mock_provider block applies to every run block below.
# mock_data / mock_resource overrides supply realistic, scenario-specific values
# for attributes that are either computed by AWS (id, arn) or read from the API
# (caller identity, region).  Concrete ARNs prevent unknown-value propagation
# through IAM policy documents and Lambda environment variables, which would
# otherwise cause assertions on downstream attributes to fail.

mock_provider "aws" {

  # ── Data sources ─────────────────────────────────────────────────────────

  # aws_iam_policy_document is a local computation (no AWS API call), but the
  # mock provider intercepts it and returns empty JSON by default.  An empty
  # string is not valid JSON, which causes the Lambda sub-module's IAM role
  # assume_role_policy to fail validation.  The override below returns a
  # minimal valid policy document so all IAM policy references resolve cleanly.
  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }

  # Simulates a production-grade AWS account in us-west-2 (the Network Manager events region).
  # account_id flows into the SNS topic resource policy (AllowPublish /
  # AllowSubscribe principal identifiers).
  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "123456789012"
      arn        = "arn:aws:iam::123456789012:user/terraform-ci"
      user_id    = "AIDAJDPLRKLG7UEXAMPLE"
    }
  }

  # Simulates the us-west-2 provider region.
  # region (not name, which is deprecated in provider v6) is returned by
  # the region_name module output via data.aws_region.current.region.
  mock_data "aws_region" {
    defaults = {
      region      = "us-west-2"
      description = "US West (Oregon)"
    }
  }

  # ── Resources ─────────────────────────────────────────────────────────────

  # Realistic Network Manager ID format: network-0<hex>.
  mock_resource "aws_networkmanager_global_network" {
    defaults = {
      id  = "network-0a1b2c3d4e5f67890"
      arn = "arn:aws:networkmanager::123456789012:global-network/network-0a1b2c3d4e5f67890"
    }
  }

  # The SNS topic ARN is used as:
  #   • The SNS_TOPIC_ARN Lambda environment variable
  #   • The resource in both IAM policy documents
  # A concrete value here prevents unknown propagation through plan evaluation.
  mock_resource "aws_sns_topic" {
    defaults = {
      arn = "arn:aws:sns:us-west-2:123456789012:networkmanager_events_mock"
    }
  }

  # The EventBridge rule ARN is used in aws_lambda_permission.source_arn.
  # A concrete value allows the source_arn assertion to evaluate cleanly.
  mock_resource "aws_cloudwatch_event_rule" {
    defaults = {
      arn = "arn:aws:events:us-west-2:123456789012:rule/default/networkmanager_events_mock"
    }
  }

  # Lambda execution role — created by the terraform-aws-modules/lambda sub-module.
  # Only computed attributes (arn, unique_id) are allowed in defaults;
  # configured attributes like name are set in the resource block and cannot
  # be overridden via mock defaults.
  mock_resource "aws_iam_role" {
    defaults = {
      arn       = "arn:aws:iam::123456789012:role/network_events_sns_publish_mock"
      unique_id = "AROAJDPLRKLG7UEXAMPLE"
    }
  }

  # IAM policy carrying the sns:Publish permission.
  mock_resource "aws_iam_policy" {
    defaults = {
      arn = "arn:aws:iam::123456789012:policy/network_events_sns_publish_mock"
    }
  }

  # Lambda function — the core compute resource of the module.
  # Only computed attributes are allowed in defaults; function_name is a
  # configured attribute set by the module call, so it is excluded here.
  mock_resource "aws_lambda_function" {
    defaults = {
      arn           = "arn:aws:lambda:us-west-2:123456789012:function:network_events_sns_publish_mock"
      qualified_arn = "arn:aws:lambda:us-west-2:123456789012:function:network_events_sns_publish_mock:$LATEST"
      invoke_arn    = "arn:aws:apigateway:us-west-2:lambda:path/2015-03-31/functions/arn:aws:lambda:us-west-2:123456789012:function:network_events_sns_publish_mock/invocations"
    }
  }

  # CloudWatch log group for Lambda function output.
  mock_resource "aws_cloudwatch_log_group" {
    defaults = {
      arn = "arn:aws:logs:us-west-2:123456789012:log-group:/aws/lambda/network_events_sns_publish_mock"
    }
  }
}

# ─────────────────────────────────────────────────────────────────────────────
# POSITIVE TESTS
# ─────────────────────────────────────────────────────────────────────────────

# ── Test: default_naming_conventions ─────────────────────────────────────────
# Scenario: An operator deploys the module with only the two required variables.
#
# Expectation: Every derived resource name embeds global_network_name as a
# suffix, giving operators a consistent, predictable naming pattern across the
# Global Network tag, SNS topic, EventBridge rule, and Lambda function.
# Drift here would make it impossible to correlate related resources in the
# AWS Console.
run "default_naming_conventions" {
  command = plan

  variables {
    global_network_name               = "prod-core-network"
    cloudwatch_logs_retention_in_days = 14
  }

  # Global Network must carry the Name tag used by the Console and other modules.
  assert {
    condition     = aws_networkmanager_global_network.global_network.tags["Name"] == "prod-core-network"
    error_message = "Global Network Name tag must equal var.global_network_name ('prod-core-network')."
  }

  # SNS topic auto-generated name must use the standard prefix.
  assert {
    condition     = aws_sns_topic.network_manager_events.name == "networkmanager_events_prod-core-network"
    error_message = "SNS topic name must default to 'networkmanager_events_<global_network_name>' when var.sns_topic_name is null."
  }

  # EventBridge rule name must be scoped to this network instance.
  assert {
    condition     = aws_cloudwatch_event_rule.network_manager_events.name == "networkmanager_events_prod-core-network"
    error_message = "EventBridge rule name must be 'networkmanager_events_<global_network_name>'."
  }

  # Lambda function name must be scoped to this network instance.
  assert {
    condition     = module.lambda_network_events_sns_publish.lambda_function_name == "network_events_sns_publish_prod-core-network"
    error_message = "Lambda function name must be 'network_events_sns_publish_<global_network_name>'."
  }
}

# ── Test: custom_sns_topic_name_overrides_default ────────────────────────────
# Scenario: An operator has existing SNS subscribers configured against a fixed
# topic ARN (e.g. "platform-network-change-events") and needs to integrate the
# module without migrating those subscriptions.
#
# Expectation: When var.sns_topic_name is set, the module must use that exact
# name verbatim — the auto-generation logic must not apply.
run "custom_sns_topic_name_overrides_default" {
  command = plan

  variables {
    global_network_name               = "eu-transit-hub"
    cloudwatch_logs_retention_in_days = 7
    sns_topic_name                    = "platform-network-change-events"
  }

  assert {
    condition     = aws_sns_topic.network_manager_events.name == "platform-network-change-events"
    error_message = "When var.sns_topic_name is provided, the SNS topic must use that custom name verbatim."
  }
}

# ── Test: default_events_bus_is_account_default ──────────────────────────────
# Scenario: Standard single-account deployment where no custom EventBridge bus
# has been configured.
#
# Expectation: AWS Network Manager publishes events to the account default bus.
# The EventBridge rule must subscribe to that same "default" bus — any other
# value would cause events to be silently missed.
run "default_events_bus_is_account_default" {
  command = plan

  variables {
    global_network_name               = "prod-core-network"
    cloudwatch_logs_retention_in_days = 14
  }

  assert {
    condition     = aws_cloudwatch_event_rule.network_manager_events.event_bus_name == "default"
    error_message = "EventBridge rule must subscribe to the 'default' event bus when var.events_bus_name is not set."
  }
}

# ── Test: custom_events_bus_applied_to_rule ──────────────────────────────────
# Scenario: A multi-account architecture forwards Network Manager events from
# the network account to a dedicated custom bus (e.g. "network-manager-forwarded-events")
# in a monitoring account.
#
# Expectation: The override bus name is applied to the EventBridge rule so the
# module works correctly in cross-account event routing topologies.
run "custom_events_bus_applied_to_rule" {
  command = plan

  variables {
    global_network_name               = "prod-core-network"
    cloudwatch_logs_retention_in_days = 14
    events_bus_name                   = "network-manager-forwarded-events"
  }

  assert {
    condition     = aws_cloudwatch_event_rule.network_manager_events.event_bus_name == "network-manager-forwarded-events"
    error_message = "EventBridge rule must use the custom event bus name provided in var.events_bus_name."
  }
}

# ── Test: sns_topic_security_properties ──────────────────────────────────────
# Scenario: A security review requires confirmation that every SNS topic in the
# account carrying network topology data is encrypted at rest and not exposed
# as a FIFO topic (which would require different subscriber configuration).
#
# Expectation: The topic uses the AWS-managed SNS KMS key regardless of other
# variable values. Creating the topic without encryption, as FIFO, or with
# content-based deduplication enabled would violate the security baseline.
run "sns_topic_security_properties" {
  command = plan

  variables {
    global_network_name               = "prod-core-network"
    cloudwatch_logs_retention_in_days = 14
  }

  # Encryption with the AWS-managed SNS key is mandatory.
  assert {
    condition     = aws_sns_topic.network_manager_events.kms_master_key_id == "alias/aws/sns"
    error_message = "SNS topic must be encrypted with the AWS-managed SNS key (alias/aws/sns)."
  }

  # Standard topic is required — Network Manager events have no ordering guarantee.
  assert {
    condition     = aws_sns_topic.network_manager_events.fifo_topic == false
    error_message = "SNS topic must be a standard (non-FIFO) topic — Network Manager events do not require strict ordering."
  }

  # Content-based deduplication is only valid for FIFO topics.
  assert {
    condition     = aws_sns_topic.network_manager_events.content_based_deduplication == false
    error_message = "content_based_deduplication must be false for standard topics."
  }
}

# ── Test: eventbridge_rule_filters_network_manager_only ──────────────────────
# Scenario: A cost review reveals the Lambda is being invoked unexpectedly
# often. An overly broad event pattern (matching all events) would cause the
# function to be called for every AWS API call in the account.
#
# Expectation: The EventBridge rule event pattern must narrowly match only
# events sourced from "aws.networkmanager", preventing false invocations and
# keeping Lambda costs proportional to actual network topology changes.
run "eventbridge_rule_filters_network_manager_only" {
  command = plan

  variables {
    global_network_name               = "prod-core-network"
    cloudwatch_logs_retention_in_days = 14
  }

  assert {
    condition     = jsondecode(aws_cloudwatch_event_rule.network_manager_events.event_pattern).source[0] == "aws.networkmanager"
    error_message = "EventBridge event pattern must filter exclusively on source 'aws.networkmanager' to avoid spurious Lambda invocations."
  }
}

# ── Test: eventbridge_lambda_invocation_chain ────────────────────────────────
# Scenario: A new engineer audits the module and wants to confirm the three
# EventBridge resources (rule, target, permission) form a coherent invocation
# chain — a misconfiguration in any link would silently prevent event delivery.
#
# Expectation:
#  • The event target references the correct rule (not a different rule in the account)
#  • The event target points at the Lambda function created by this module
#  • The Lambda resource policy allows invocation from the EventBridge principal
#  • The Lambda resource policy grants only the minimum required action
run "eventbridge_lambda_invocation_chain" {
  command = plan

  variables {
    global_network_name               = "prod-core-network"
    cloudwatch_logs_retention_in_days = 14
  }

  # Target must reference the network_manager_events rule, not a hardcoded name.
  assert {
    condition     = aws_cloudwatch_event_target.network_manager_events.rule == aws_cloudwatch_event_rule.network_manager_events.id
    error_message = "EventBridge target must reference the Network Manager event rule created by this module."
  }

  # Target ARN must point at the Lambda function from the lambda sub-module.
  assert {
    condition     = aws_cloudwatch_event_target.network_manager_events.arn == module.lambda_network_events_sns_publish.lambda_function_arn
    error_message = "EventBridge target ARN must point to the Lambda function created by this module."
  }

  # Lambda resource policy must use the EventBridge service principal.
  assert {
    condition     = aws_lambda_permission.network_manager_events.principal == "events.amazonaws.com"
    error_message = "Lambda permission principal must be 'events.amazonaws.com' (EventBridge service principal)."
  }

  # Only lambda:InvokeFunction is required — nothing broader.
  assert {
    condition     = aws_lambda_permission.network_manager_events.action == "lambda:InvokeFunction"
    error_message = "Lambda permission must allow 'lambda:InvokeFunction' — no broader action is necessary."
  }

  # Stable, human-readable statement ID simplifies CloudTrail audit trails.
  assert {
    condition     = aws_lambda_permission.network_manager_events.statement_id == "AllowExecutionFromEvents"
    error_message = "Lambda permission statement_id must be 'AllowExecutionFromEvents' for operational traceability."
  }
}

# ── Test: lambda_permission_scoped_to_rule ───────────────────────────────────
# Scenario: The account contains multiple EventBridge rules that invoke Lambda
# functions. A misconfigured Lambda resource policy with an open source_arn
# would allow any EventBridge rule in the account to invoke this function,
# leaking network topology events to unintended consumers or causing
# unexpected invocations.
#
# Expectation: The Lambda permission source_arn must reference the specific
# EventBridge rule created by this module — not "*" or any other rule.
run "lambda_permission_scoped_to_rule" {
  command = plan

  variables {
    global_network_name               = "prod-core-network"
    cloudwatch_logs_retention_in_days = 14
  }

  assert {
    condition     = aws_lambda_permission.network_manager_events.source_arn == aws_cloudwatch_event_rule.network_manager_events.arn
    error_message = "Lambda permission source_arn must be scoped to the specific EventBridge rule created by this module, not open to all EventBridge rules."
  }
}

# ── Test: module_outputs_wired_correctly ─────────────────────────────────────
# Scenario: Downstream Terraform modules consume this module's outputs via
# remote state (global_network_id, sns_topic_arn, region_name). A broken
# output reference (e.g. referencing a renamed resource) would cause silent
# failures in all consuming configurations.
#
# Expectation: The region_name output resolves to the mocked region "us-west-2",
# confirming it is wired to the aws_region data source and not hardcoded.
run "module_outputs_wired_correctly" {
  command = plan

  variables {
    global_network_name               = "prod-core-network"
    cloudwatch_logs_retention_in_days = 14
  }

  # region_name must come from the aws_region data source (mocked to us-west-2).
  assert {
    condition     = output.region_name == "us-west-2"
    error_message = "output.region_name must reflect the deployment region from the aws_region data source, not a hardcoded value."
  }
}

# ─────────────────────────────────────────────────────────────────────────────
# NEGATIVE TESTS
# ─────────────────────────────────────────────────────────────────────────────

# ── Test: reject_unrecognised_logging_level ───────────────────────────────────
# Scenario: An operator mistakenly sets lambda_logging_level to "VERBOSE",
# expecting Python-style verbosity control. The Lambda handler only branches on
# WARN, INFO, and DEBUG; any other value would result in a silently incorrect
# logging configuration that is difficult to diagnose in production.
#
# Expectation: The variable validation rule must reject "VERBOSE" at plan time
# with a clear error, preventing a misconfigured deployment from reaching CI.
run "reject_unrecognised_logging_level" {
  command = plan

  variables {
    global_network_name               = "prod-core-network"
    cloudwatch_logs_retention_in_days = 14
    lambda_logging_level              = "VERBOSE"
  }

  expect_failures = [var.lambda_logging_level]
}

# ── Test: reject_standard_python_log_level ───────────────────────────────────
# Scenario: An operator who is familiar with Python's standard logging module
# sets lambda_logging_level to "ERROR", assuming the module follows Python's
# logging hierarchy (DEBUG < INFO < WARNING < ERROR < CRITICAL). The module
# does not support "ERROR" — only WARN, INFO, and DEBUG are valid.
#
# Expectation: The variable validation rule rejects "ERROR" at plan time,
# preventing an operator from deploying a Lambda function that would silently
# log nothing at the WARN level (since the handler treats unknown values as WARN
# with no code path to ERROR-level filtering).
run "reject_standard_python_log_level" {
  command = plan

  variables {
    global_network_name               = "prod-core-network"
    cloudwatch_logs_retention_in_days = 14
    lambda_logging_level              = "ERROR"
  }

  expect_failures = [var.lambda_logging_level]
}

# ─────────────────────────────────────────────────────────────────────────────
# Test: Network Manager events region
# ─────────────────────────────────────────────────────────────────────────────
#
# Network Manager publishes its EventBridge events in us-west-2 only. Deploying
# the rule anywhere else produces a rule that never fires: the check block
# reports it.

run "warn_when_not_deployed_in_us_west_2" {
  command = plan

  variables {
    global_network_name = "eu-deployed"
  }

  override_data {
    target = data.aws_region.current
    values = {
      region = "eu-west-1"
    }
  }

  expect_failures = [check.network_manager_events_region]
}

# ─────────────────────────────────────────────────────────────────────────────
# Test: Lambda timeout and failed invocations
# ─────────────────────────────────────────────────────────────────────────────

run "lambda_timeout_and_no_failure_destination_by_default" {
  command = plan

  variables {
    global_network_name = "prod-core-network"
  }

  assert {
    condition     = output.lambda_timeout == 30
    error_message = "The publisher only calls sns:Publish once; the timeout must be 30 s."
  }

  assert {
    condition     = output.lambda_destination_on_failure_arn == null
    error_message = "No failure destination must be configured by default."
  }
}

run "failure_destination_is_configured" {
  command = plan

  variables {
    global_network_name               = "prod-core-network"
    lambda_destination_on_failure_arn = "arn:aws:sqs:us-west-2:123456789012:network_manager_events_failures"
  }

  assert {
    condition     = output.lambda_destination_on_failure_arn == "arn:aws:sqs:us-west-2:123456789012:network_manager_events_failures"
    error_message = "Failed asynchronous invocations must be sent to lambda_destination_on_failure_arn."
  }
}
