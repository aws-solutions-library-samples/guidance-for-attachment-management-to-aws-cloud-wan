# ─── Input Validation Failure Tests ──────────────────────────────────────────
# Negative tests: verify that invalid lambda_logging_level values are rejected
# at plan time before any resource is created, and that all three valid values
# are accepted.
#
# These tests use command=plan so the Lambda module override is not needed
# (validation fires before any resource planning occurs).

mock_provider "aws" {
  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\",\"Principal\":{\"Service\":\"lambda.amazonaws.com\"}}]}"
    }
  }
  mock_resource "aws_iam_role" {
    defaults = {
      arn = "arn:aws:iam::123456789012:role/mock-cloudwan-validation-lambda-role"
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
    defaults = { region = "eu-west-1" }
  }
  mock_resource "aws_sqs_queue" {
    defaults = {
      arn = "arn:aws:sqs:eu-west-1:123456789012:cloudwan-validation"
      url = "https://sqs.eu-west-1.amazonaws.com/123456789012/cloudwan-validation"
      id  = "https://sqs.eu-west-1.amazonaws.com/123456789012/cloudwan-validation"
    }
  }
  mock_resource "aws_sns_topic_subscription" {
    defaults = {
      arn = "arn:aws:sns:us-west-2:111111111111:network_manager_events:sub-validation"
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
      arn = "arn:aws:sns:us-west-2:111111111111:network_manager_events:sub-validation"
    }
  }
}

# Base variables used by every run block.
variables {
  name                              = "cloudwan-validation"
  aws_account_reader_role_arn       = "arn:aws:iam::000000000000:role/org-reader"
  network_events_sns_topic_region   = "us-west-2"
  network_events_sns_topic_arn      = "arn:aws:sns:us-west-2:111111111111:network_manager_events"
  global_network_id                 = "global-network-0a1b2c3d4e5f6a7b8"
  cloudwatch_logs_retention_in_days = 7
}

# ─── Negative tests (expect validation failure) ────────────────────────────────

run "invalid_logging_level_VERBOSE_is_rejected" {
  command = plan

  variables {
    # "VERBOSE" is not supported — the Lambda handler only branches on WARN/INFO/DEBUG.
    lambda_logging_level = "VERBOSE"
  }

  expect_failures = [var.lambda_logging_level]
}

run "invalid_logging_level_lowercase_warn_is_rejected" {
  command = plan

  variables {
    # The Lambda uses exact string equality; "warn" != "WARN".
    lambda_logging_level = "warn"
  }

  expect_failures = [var.lambda_logging_level]
}

run "invalid_logging_level_ERROR_is_rejected" {
  command = plan

  variables {
    # "ERROR" is a valid Python level but is not in the allowed set —
    # the Lambda handler does not define behaviour for it.
    lambda_logging_level = "ERROR"
  }

  expect_failures = [var.lambda_logging_level]
}

# ─── Positive boundary tests (all three valid values must be accepted) ─────────

run "valid_logging_level_WARN_is_accepted" {
  command = plan
  variables { lambda_logging_level = "WARN" }
  assert {
    condition     = var.lambda_logging_level == "WARN"
    error_message = "WARN must be accepted as a valid logging level."
  }
}

run "valid_logging_level_INFO_is_accepted" {
  command = plan
  variables { lambda_logging_level = "INFO" }
  assert {
    condition     = var.lambda_logging_level == "INFO"
    error_message = "INFO must be accepted as a valid logging level."
  }
}

run "valid_logging_level_DEBUG_is_accepted" {
  command = plan
  variables { lambda_logging_level = "DEBUG" }
  assert {
    condition     = var.lambda_logging_level == "DEBUG"
    error_message = "DEBUG must be accepted as a valid logging level."
  }
}

# ─── cloudwatch_logs_retention_in_days validation ──────────────────────────────

run "invalid_cloudwatch_retention_42_is_rejected" {
  command = plan
  variables { cloudwatch_logs_retention_in_days = 42 }
  expect_failures = [var.cloudwatch_logs_retention_in_days]
}

run "valid_cloudwatch_retention_30_is_accepted" {
  command = plan
  variables { cloudwatch_logs_retention_in_days = 30 }
  assert {
    condition     = var.cloudwatch_logs_retention_in_days == 30
    error_message = "30 must be accepted as a valid retention period."
  }
}

# ─── sqs_delay_seconds validation ─────────────────────────────────────────────

run "invalid_sqs_delay_901_is_rejected" {
  command = plan
  variables { sqs_delay_seconds = 901 }
  expect_failures = [var.sqs_delay_seconds]
}

run "invalid_sqs_delay_negative_is_rejected" {
  command = plan
  variables { sqs_delay_seconds = -1 }
  expect_failures = [var.sqs_delay_seconds]
}

run "valid_sqs_delay_300_is_accepted" {
  command = plan
  variables { sqs_delay_seconds = 300 }
  assert {
    condition     = var.sqs_delay_seconds == 300
    error_message = "300 must be accepted as a valid SQS delay."
  }
}

# ─── name validation ──────────────────────────────────────────────────────────

run "invalid_name_special_chars_is_rejected" {
  command = plan
  variables { name = "cloudwan@invalid!" }
  expect_failures = [var.name]
}

run "invalid_name_empty_is_rejected" {
  command = plan
  variables { name = "" }
  expect_failures = [var.name]
}

# ─── aws_account_reader_role_arn validation ───────────────────────────────────

run "invalid_arn_format_is_rejected" {
  command = plan
  variables { aws_account_reader_role_arn = "not-an-arn" }
  expect_failures = [var.aws_account_reader_role_arn]
}

run "valid_arn_format_is_accepted" {
  command = plan
  variables { aws_account_reader_role_arn = "arn:aws:iam::123456789012:role/my-role" }
  assert {
    condition     = var.aws_account_reader_role_arn == "arn:aws:iam::123456789012:role/my-role"
    error_message = "Valid IAM role ARN must be accepted."
  }
}

# ─── Segment name validation (letters and numbers only) ───────────────────────

run "invalid_full_return_table_with_hyphen_is_rejected" {
  command = plan
  variables { full_return_table = "full-return" }
  expect_failures = [var.full_return_table]
}

run "valid_full_return_table_is_accepted" {
  command = plan
  variables { full_return_table = "fullreturn" }
  assert {
    condition     = var.full_return_table == "fullreturn"
    error_message = "Alphanumeric full_return_table must be accepted."
  }
}

run "invalid_full_return_table_by_region_with_underscore_is_rejected" {
  command = plan
  variables { full_return_table_by_region = { "eu-west-1" = "inspection_euw1" } }
  expect_failures = [var.full_return_table_by_region]
}

run "valid_full_return_table_by_region_is_accepted" {
  command = plan
  variables { full_return_table_by_region = { "eu-west-1" = "inspectioneuw1" } }
  assert {
    condition     = var.full_return_table_by_region["eu-west-1"] == "inspectioneuw1"
    error_message = "Alphanumeric full_return_table_by_region values must be accepted."
  }
}

run "invalid_quarantine_table_is_rejected" {
  command = plan
  variables { cloudwan_quarantine_table = "quarantine-segment" }
  expect_failures = [var.cloudwan_quarantine_table]
}

run "invalid_quarantineroutes_table_is_rejected" {
  command = plan
  variables { cloudwan_quarantineroutes_table = "quarantine_routes" }
  expect_failures = [var.cloudwan_quarantineroutes_table]
}

run "invalid_address_map_segment_name_is_rejected" {
  command = plan
  variables {
    vpc_segment_address_map = { "non-prod" = { "eu-west-1" = ["10.2.0.0/16"] } }
  }
  expect_failures = [var.vpc_segment_address_map]
}

run "valid_full_return_table_empty_is_accepted" {
  command = plan
  variables {
    full_return_table           = ""
    full_return_table_by_region = { "eu-west-1" = "inspectioneuw1", "eu-west-2" = "inspectioneuw2" }
  }
  assert {
    condition     = var.full_return_table == "" && length(var.full_return_table_by_region) == 2
    error_message = "An empty full_return_table with regional inspection segments must be accepted."
  }
}

# ─── lambda_sqs_maximum_concurrency validation ────────────────────────────────

run "invalid_sqs_maximum_concurrency_1_is_rejected" {
  command = plan
  variables { lambda_sqs_maximum_concurrency = 1 }
  expect_failures = [var.lambda_sqs_maximum_concurrency]
}

run "invalid_sqs_maximum_concurrency_1001_is_rejected" {
  command = plan
  variables { lambda_sqs_maximum_concurrency = 1001 }
  expect_failures = [var.lambda_sqs_maximum_concurrency]
}

run "valid_sqs_maximum_concurrency_2_is_accepted" {
  command = plan
  variables { lambda_sqs_maximum_concurrency = 2 }
  assert {
    condition     = var.lambda_sqs_maximum_concurrency == 2
    error_message = "2 must be accepted as the minimum SQS maximum concurrency."
  }
}
