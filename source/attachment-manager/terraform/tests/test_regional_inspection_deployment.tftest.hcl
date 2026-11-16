# ─── Regional Inspection Deployment Test ──────────────────────────────────────
# Positive test: every region has had its last-hop loopback removed, so there is
# no global full return segment (full_return_table = ""). Conflicting routes are
# checked in the regional inspection segment of each edge instead
# (full_return_table_by_region). Regions missing from the map are admitted
# without the conflict check (the Lambda logs SKIP_CONFLICT_CHECK).
#
# Scenario: the Lambda runs in eu-west-1, the core network spans eu-west-1 and
# eu-west-2, and the Network Manager events topic lives in us-west-2.
#
# All run blocks use command=plan with mocked providers (no credentials).

mock_provider "aws" {
  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\",\"Principal\":{\"Service\":\"lambda.amazonaws.com\"}}]}"
    }
  }
  mock_resource "aws_iam_role" {
    defaults = {
      arn = "arn:aws:iam::123456789012:role/mock-cloudwan-regional-lambda-role"
    }
  }
  mock_resource "aws_lambda_function" {
    defaults = {
      arn        = "arn:aws:lambda:eu-west-1:123456789012:function:cloudwan-regional_eu-west-1_routing"
      invoke_arn = "arn:aws:apigateway:eu-west-1:lambda:path/2015-03-31/functions/arn:aws:lambda:eu-west-1:123456789012:function:cloudwan-regional_eu-west-1_routing/invocations"
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
      arn = "arn:aws:sqs:eu-west-1:123456789012:cloudwan-regional"
      url = "https://sqs.eu-west-1.amazonaws.com/123456789012/cloudwan-regional"
      id  = "https://sqs.eu-west-1.amazonaws.com/123456789012/cloudwan-regional"
    }
  }
  mock_resource "aws_sns_topic_subscription" {
    defaults = {
      arn = "arn:aws:sns:us-west-2:111111111111:network_manager_events:sub-regional-abc123"
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
      arn = "arn:aws:sns:us-west-2:111111111111:network_manager_events:sub-regional-abc123"
    }
  }
  mock_resource "aws_cloudwatch_metric_alarm" {
    defaults = {
      arn = "arn:aws:cloudwatch:eu-west-1:123456789012:alarm:cloudwan-regional_dlq_messages"
      id  = "cloudwan-regional_dlq_messages"
    }
  }
}

# Mocking the external provider prevents the lambda module's package.py build
# script from executing during the plan. The returned mock values satisfy all
# downstream references to data.external.archive_prepare[0].result.* .
mock_provider "external" {
  mock_data "external" {
    defaults = {
      result = {
        filename            = "/tmp/mock-lambda-cloudwan-regional.zip"
        build_plan          = "{}"
        build_plan_filename = "/tmp/mock-build-plan-cloudwan-regional.json"
        timestamp           = "1000000000"
      }
    }
  }
}

# Explicit id prevents the mock framework from crashing on null_resource.archive,
# which has a provisioner block that the auto-schema composer cannot handle.
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

# Regional inspection segments only — no global full return segment.
variables {
  name                            = "cloudwan-regional"
  aws_account_reader_role_arn     = "arn:aws:iam::000000000000:role/org-reader"
  network_events_sns_topic_region = "us-west-2"
  network_events_sns_topic_arn    = "arn:aws:sns:us-west-2:111111111111:network_manager_events"
  global_network_id               = "global-network-0a1b2c3d4e5f6a7b8"
  core_network_arn                = "arn:aws:networkmanager:us-east-1:111111111111:core-network/c0123456789abcdef"
  full_return_table               = ""
  full_return_table_by_region = {
    "eu-west-1" = "inspectioneuw1"
    "eu-west-2" = "inspectioneuw2"
  }
  lambda_sqs_maximum_concurrency    = 2
  cloudwatch_logs_retention_in_days = 30
}

# ─── Full return table resolution ─────────────────────────────────────────────

run "no_global_full_return_table" {
  command = plan

  assert {
    condition     = output.lambda_env_full_return_table == ""
    error_message = "FULL_RETURN_TABLE must be empty when only regional inspection segments are used."
  }
}

run "regional_inspection_segments_are_passed_to_lambda" {
  command = plan

  assert {
    condition = jsondecode(output.lambda_env_full_return_table_by_region) == {
      "eu-west-1" = "inspectioneuw1"
      "eu-west-2" = "inspectioneuw2"
    }
    error_message = "FULL_RETURN_TABLE_BY_REGION must carry one inspection segment per region."
  }
}

# ─── SNS subscription ─────────────────────────────────────────────────────────

run "sns_subscription_is_created_in_topic_region" {
  command = plan

  # Subscribe must be called in the topic region (us-west-2), not in the
  # Lambda region nor the region of the aliased provider.
  assert {
    condition     = output.sns_subscription_region == "us-west-2"
    error_message = "SNS subscription must default to network_events_sns_topic_region. Got: ${output.sns_subscription_region}"
  }

  assert {
    condition = jsondecode(output.sns_filter_policy).coreUplinkArn == [
      "arn:aws:networkmanager:us-east-1:111111111111:core-network/c0123456789abcdef"
    ]
    error_message = "SNS filter policy must restrict events to the managed core network ARN."
  }
}

run "sns_subscription_region_override" {
  command = plan

  variables {
    region_sns_topic_subscription = "us-east-1"
  }

  assert {
    condition     = output.sns_subscription_region == "us-east-1"
    error_message = "region_sns_topic_subscription must override the topic region."
  }
}

# ─── SQS processing ───────────────────────────────────────────────────────────

run "event_source_mapping_limits_concurrency_without_throttling" {
  command = plan

  assert {
    condition     = aws_lambda_event_source_mapping.attachment_created.scaling_config[0].maximum_concurrency == 2
    error_message = "lambda_sqs_maximum_concurrency must be set on the event source mapping scaling_config."
  }

  assert {
    condition     = aws_lambda_event_source_mapping.attachment_created.function_response_types == toset(["ReportBatchItemFailures"])
    error_message = "Retries rely on ReportBatchItemFailures."
  }
}

run "dlq_keeps_messages_for_14_days" {
  command = plan

  assert {
    condition     = aws_sqs_queue.cloudwan_tag_dlq.message_retention_seconds == 1209600
    error_message = "DLQ retention must be 14 days."
  }
}

# ─── IP address plan file ─────────────────────────────────────────────────────

run "address_map_is_not_written_without_a_map" {
  command = plan

  assert {
    condition     = length(local_file.vpc_segment_address_map) == 0
    error_message = "No address map file must be written when vpc_segment_address_map is null."
  }

  assert {
    condition     = output.lambda_env_segment_addressing_file == ""
    error_message = "SEGMENT_ADDRESSING_FILE must be empty without an address map."
  }
}
