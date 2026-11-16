# IAM inline policy attached to the Lambda execution role.
# Each statement grants only the permissions required for one concern.
data "aws_iam_policy_document" "lambda_routing_config_on_demand" {

  # The Lambda assumes this cross-account role to read AWS Organizations account
  # tags (specifically the "route-domain" tag), which determines the target segment
  # for each attaching VPC.
  statement {
    effect    = "Allow"
    actions   = ["sts:AssumeRole"]
    resources = [var.aws_account_reader_role_arn]
  }

  # SQS permissions on the main queue required by the event source mapping to
  # receive, process, and delete messages. Messages that need a retry are
  # reported back as batch item failures and redelivered by SQS.
  statement {
    effect = "Allow"
    actions = [
      "sqs:ReceiveMessage",
      "sqs:DeleteMessage",
      "sqs:GetQueueAttributes",
    ]
    resources = [aws_sqs_queue.cloudwan_tag.arn]
  }

  # NetworkManager permissions needed across all attachment lifecycle actions:
  #   - Get*/List*                        → read current attachment and route state
  #   - DeleteAttachment                  → remove non-compliant VPC attachments
  #   - TagResource                       → write the segment (route-domain) tag
  statement {
    effect = "Allow"
    actions = [
      "networkmanager:Get*",
      "networkmanager:List*",
      "networkmanager:DeleteAttachment",
      "networkmanager:TagResource",
    ]
    # Cloud WAN resources do not support resource-level ARN conditions in IAM.
    resources = ["*"]
  }
}


# Queue policy that allows the SNS topic to send messages to the SQS queue.
# The ArnEquals condition prevents confused-deputy attacks by ensuring only
# the specific network-events topic can write to this queue.
data "aws_iam_policy_document" "sqs_cloudwan_tag" {
  statement {
    effect    = "Allow"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.cloudwan_tag.arn]

    principals {
      type        = "Service"
      identifiers = ["sns.amazonaws.com"]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [var.network_events_sns_topic_arn]
    }
  }
}
