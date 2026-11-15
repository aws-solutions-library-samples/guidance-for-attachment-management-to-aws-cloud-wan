# ─── Minimal Deployment Test ──────────────────────────────────────────────────
# Positive test: verifies the null/empty code paths when only required inputs
# are provided — no core_network_arn, no vpc_segment_address_map, no
# full_return_table. All optional features are disabled.
#
# Scenario: a new deployment where IP-range validation and conflict detection
# are not yet configured. The SNS topic carries events for a single core network
# so no SNS filter is needed.
#
# All run blocks use command=plan. Lambda packaging provisioners never execute
# during plan; mock providers for external, null, and local allow the Lambda
# module to be planned without running any build scripts.

mock_provider "aws" {
  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\",\"Principal\":{\"Service\":\"lambda.amazonaws.com\"}}]}"
    }
  }
  mock_resource "aws_iam_role" {
    defaults = {
      arn = "arn:aws:iam::123456789012:role/mock-cloudwan-minimal-lambda-role"
    }
  }
  mock_resource "aws_lambda_function" {
    defaults = {
      arn        = "arn:aws:lambda:eu-west-1:123456789012:function:cloudwan-minimal_eu-west-1_routing"
      invoke_arn = "arn:aws:apigateway:eu-west-1:lambda:path/2015-03-31/functions/arn:aws:lambda:eu-west-1:123456789012:function:cloudwan-minimal_eu-west-1_routing/invocations"
    }
  }
  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "123456789012"
      arn        = "arn:aws:iam::123456789012:root"
      user_id    = "123456789012"
    }
  }
  mock_data "aws_region" {
    defaults = {
      region      = "eu-west-1"
      description = "Europe (Ireland)"
    }
  }
  mock_resource "aws_sqs_queue" {
    defaults = {
      arn = "arn:aws:sqs:eu-west-1:123456789012:cloudwan-minimal"
      url = "https://sqs.eu-west-1.amazonaws.com/123456789012/cloudwan-minimal"
      id  = "https://sqs.eu-west-1.amazonaws.com/123456789012/cloudwan-minimal"
    }
  }
  mock_resource "aws_sns_topic_subscription" {
    defaults = {
      arn = "arn:aws:sns:us-west-2:111111111111:network_manager_events:sub-minimal"
    }
  }
}

mock_provider "aws" {
  alias = "aws_sns_subscribe"
  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}"
    }
  }
  mock_data "aws_caller_identity" {
    defaults = { account_id = "123456789012" }
  }
  mock_resource "aws_sns_topic_subscription" {
    defaults = {
      arn = "arn:aws:sns:us-west-2:111111111111:network_manager_events:sub-minimal"
    }
  }
}

mock_provider "external" {
  mock_data "external" {
    defaults = {
      result = {
        filename            = "/tmp/mock-lambda-cloudwan-minimal.zip"
        build_plan          = "{}"
        build_plan_filename = "/tmp/mock-build-plan-cloudwan-minimal.json"
        timestamp           = "1000000000"
      }
    }
  }
}

mock_provider "null" {
  mock_resource "null_resource" {
    defaults = { id = "mock-archive-id" }
  }
}

mock_provider "local" {
  mock_resource "local_file" {
    defaults = {
      id                   = "mock-local-file-id"
      content_md5          = "d41d8cd98f00b204e9800998ecf8427e"
      content_sha1         = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
      content_sha256       = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      content_sha512       = "cf83e1357eef8cbdf1702098e739b3e3a29c30b02e04f7c4b9d2c9df0a2f9b6eb5f"
      content_base64sha256 = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
      content_base64sha512 = "z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c4="
    }
  }
}

# Required variables only; all optional inputs use module defaults.
variables {
  name                              = "cloudwan-minimal"
  aws_account_reader_role_arn       = "arn:aws:iam::000000000000:role/org-reader"
  network_events_sns_topic_region   = "us-west-2"
  network_events_sns_topic_arn      = "arn:aws:sns:us-west-2:111111111111:network_manager_events"
  global_network_id                 = "global-network-0a1b2c3d4e5f6a7b8"
  cloudwatch_logs_retention_in_days = 7

  # Explicitly null to exercise the no-filter / no-addressing-map code paths.
  core_network_arn        = null
  vpc_segment_address_map = null
  full_return_table       = ""
}

run "sns_filter_is_unset_when_no_core_network_arn" {
  command = plan

  # When core_network_arn is null, no filter policy is set so ALL events are
  # forwarded — appropriate when a single deployment owns the only core network
  # on this topic. (SNS rejects filter policies with empty value lists.)
  assert {
    condition     = output.sns_filter_policy == null
    error_message = "SNS filter policy must not be set when core_network_arn is null."
  }
}

run "sqs_queue_and_dlq_created_with_minimal_inputs" {
  command = plan

  assert {
    condition     = output.sqs_queue_name == "cloudwan-minimal"
    error_message = "SQS queue must be created even with minimal inputs."
  }

  assert {
    condition     = output.sqs_dlq_name == "cloudwan-minimal_dlq"
    error_message = "DLQ must be created even with minimal inputs."
  }

  assert {
    condition     = output.sqs_max_receive_count == 5
    error_message = "DLQ redrive count must be 5 regardless of other inputs."
  }
}
