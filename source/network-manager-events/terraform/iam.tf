# ─────────────────────────────────────────────────────────────────────────────
# IAM — Lambda execution policy (inline, attached to the Lambda role)
# ─────────────────────────────────────────────────────────────────────────────
#
# Grants the Lambda function the minimum permission needed to publish enriched
# Network Manager events to the SNS topic. This document is passed to the
# lambda module via `policy_json` and attached to the auto-generated execution
# role alongside AWSLambdaBasicExecutionRole.

data "aws_iam_policy_document" "lambda_network_manager_events" {
  statement {
    sid    = "AllowPublish"
    effect = "Allow"

    actions = [
      "sns:Publish",
    ]

    # Scoped to the specific SNS topic created by this module — prevents
    # the Lambda from publishing to any other topic in the account.
    resources = [
      aws_sns_topic.network_manager_events.arn,
    ]
  }
}

# ─────────────────────────────────────────────────────────────────────────────
# IAM — SNS topic resource policy
# ─────────────────────────────────────────────────────────────────────────────
#
# Defines the SNS topic's own resource-based policy. Grants the owning AWS
# account:
#   sns:Publish   — so the Lambda (and other account principals) can send messages
#   sns:Subscribe — so downstream consumers can create filter subscriptions

data "aws_iam_policy_document" "sns_network_manager_events" {
  # Allow any principal in the owning account to publish to the topic.
  # The Lambda's execution role IAM policy (above) provides the specific
  # identity-based permission; this statement enables the corresponding
  # resource-side allowance.
  statement {
    sid    = "AllowPublish"
    effect = "Allow"

    actions = [
      "sns:Publish",
    ]

    resources = [
      aws_sns_topic.network_manager_events.arn,
    ]

    principals {
      type = "AWS"
      # Restrict to identities within the account that owns the topic.
      identifiers = [data.aws_caller_identity.current.account_id]
    }
  }

  # Allow any principal in the owning account to subscribe.
  # Consumers (SQS queues, Lambda functions, HTTP endpoints) need this
  # to create or manage their subscriptions via the AWS Console or API.
  statement {
    sid    = "AllowSubscribe"
    effect = "Allow"

    actions = [
      "sns:Subscribe",
    ]

    resources = [
      aws_sns_topic.network_manager_events.arn,
    ]

    principals {
      type = "AWS"
      # Restrict to identities within the account that owns the topic.
      identifiers = [data.aws_caller_identity.current.account_id]
    }
  }
}
