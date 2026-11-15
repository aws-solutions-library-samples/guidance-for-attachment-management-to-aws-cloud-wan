# ─── Full Deployment Test ──────────────────────────────────────────────────────
# Positive test: verifies SQS and SNS configuration when the module is given a
# complete set of inputs — core network ARN, full-return table, and a region
# specific full-return table (regional inspection segment without loopback).
#
# Scenario: a centralised-networking account managing a Cloud WAN core network
# across two European regions. The SNS topic lives in us-west-2 (where AWS
# Network Manager events are published) while the Lambda runs in eu-west-1.
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
      arn = "arn:aws:iam::123456789012:role/mock-cloudwan-prod-lambda-role"
    }
  }
  mock_resource "aws_lambda_function" {
    defaults = {
      arn        = "arn:aws:lambda:eu-west-1:123456789012:function:cloudwan-prod_eu-west-1_routing"
      invoke_arn = "arn:aws:apigateway:eu-west-1:lambda:path/2015-03-31/functions/arn:aws:lambda:eu-west-1:123456789012:function:cloudwan-prod_eu-west-1_routing/invocations"
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
      arn = "arn:aws:sqs:eu-west-1:123456789012:cloudwan-prod"
      url = "https://sqs.eu-west-1.amazonaws.com/123456789012/cloudwan-prod"
      id  = "https://sqs.eu-west-1.amazonaws.com/123456789012/cloudwan-prod"
    }
  }
  mock_resource "aws_sns_topic_subscription" {
    defaults = {
      arn = "arn:aws:sns:us-west-2:111111111111:network_manager_events:sub-prod-abc123"
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
      arn = "arn:aws:sns:us-west-2:111111111111:network_manager_events:sub-prod-abc123"
    }
  }
  mock_resource "aws_cloudwatch_metric_alarm" {
    defaults = {
      arn = "arn:aws:cloudwatch:eu-west-1:123456789012:alarm:cloudwan-prod_dlq_messages"
      id  = "cloudwan-prod_dlq_messages"
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
        filename            = "/tmp/mock-lambda-cloudwan-prod.zip"
        build_plan          = "{}"
        build_plan_filename = "/tmp/mock-build-plan-cloudwan-prod.json"
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

# Required module variables — full deployment scenario.
variables {
  name                              = "cloudwan-prod"
  aws_account_reader_role_arn       = "arn:aws:iam::000000000000:role/org-reader"
  network_events_sns_topic_region   = "us-west-2"
  network_events_sns_topic_arn      = "arn:aws:sns:us-west-2:111111111111:network_manager_events"
  global_network_id                 = "global-network-0a1b2c3d4e5f6a7b8"
  core_network_arn                  = "arn:aws:networkmanager:us-east-1:111111111111:core-network/c0123456789abcdef"
  full_return_table                 = "fullreturn"
  full_return_table_by_region       = { "eu-west-1" = "inspectioneuw1" }
  cloudwatch_logs_retention_in_days = 30
  # vpc_segment_address_map is not set here: yamlencode(map(any)) triggers a
  # known OpenTofu 1.11.5 mock-value-composer bug (unknown-length map panic).
  # The vpc_segment_address_map code path is exercised by Lambda unit tests.
}

# ─── SQS Queue Configuration ──────────────────────────────────────────────────

run "sqs_queue_name_matches_var_name" {
  command = plan

  assert {
    condition     = output.sqs_queue_name == "cloudwan-prod"
    error_message = "SQS queue name must equal var.name. Got: ${output.sqs_queue_name}"
  }
}

run "sqs_dlq_name_is_name_plus_suffix" {
  command = plan

  assert {
    condition     = output.sqs_dlq_name == "cloudwan-prod_dlq"
    error_message = "DLQ name must be '{name}_dlq'. Got: ${output.sqs_dlq_name}"
  }
}

run "sqs_visibility_timeout_exceeds_lambda_timeout" {
  command = plan

  # 125 s visibility timeout > 90 s Lambda timeout prevents the same message
  # becoming visible again while the Lambda is still processing it.
  assert {
    condition     = output.sqs_queue_visibility_timeout_seconds == 125
    error_message = "SQS visibility timeout must be 125 s (> Lambda 90 s timeout). Got: ${output.sqs_queue_visibility_timeout_seconds}"
  }
}

run "sqs_default_delay_is_zero" {
  command = plan

  assert {
    condition     = output.sqs_queue_delay_seconds == 0
    error_message = "Default SQS delay must be 0 s. Got: ${output.sqs_queue_delay_seconds}"
  }
}

run "sqs_redrive_policy_retries_five_times_before_dlq" {
  command = plan

  # Five retries give Cloud WAN time to resolve transient API errors without
  # looping indefinitely on permanently broken attachments.
  assert {
    condition     = output.sqs_max_receive_count == 5
    error_message = "DLQ redrive maxReceiveCount must be 5. Got: ${output.sqs_max_receive_count}"
  }
}

# ─── SNS Subscription Filter Policy ──────────────────────────────────────────

run "sns_filter_policy_restricts_to_managed_core_network" {
  command = plan

  # The filter must contain exactly the managed core network ARN so that events
  # from other core networks sharing the same SNS topic are not forwarded.
  assert {
    condition = jsondecode(output.sns_filter_policy).coreUplinkArn == [
      "arn:aws:networkmanager:us-east-1:111111111111:core-network/c0123456789abcdef"
    ]
    error_message = "SNS filter policy must restrict events to the managed core network ARN."
  }
}

# ─── Full return table resolution ─────────────────────────────────────────────

run "full_return_table_by_region_is_passed_to_lambda" {
  command = plan

  assert {
    condition     = jsondecode(output.lambda_env_full_return_table_by_region) == { "eu-west-1" = "inspectioneuw1" }
    error_message = "FULL_RETURN_TABLE_BY_REGION must carry the region to segment map."
  }

  assert {
    condition     = output.lambda_env_full_return_table == "fullreturn"
    error_message = "FULL_RETURN_TABLE must carry the default full return segment."
  }
}

# ─── DLQ Alarm ────────────────────────────────────────────────────────────────

run "dlq_alarm_is_created_by_default" {
  command = plan

  assert {
    condition     = output.dlq_alarm_arn != null
    error_message = "DLQ alarm must be created when dlq_alarm_enabled defaults to true."
  }
}
