# Get account id
data "aws_caller_identity" "current" {}


# Get region
data "aws_region" "current" {}


# Create new global network
resource "aws_networkmanager_global_network" "global_network" {
  tags = {
    Name = var.global_network_name
  }
}


# Lambda: SNS enrich message attributes
# https://registry.terraform.io/modules/terraform-aws-modules/lambda/aws/latest
module "lambda_network_events_sns_publish" {
  source                            = "terraform-aws-modules/lambda/aws"
  function_name                     = "${var.global_network_name}_network_events_sns_publish"
  handler                           = "lambda_handler.handler"
  runtime                           = "python3.9"
  source_path                       = "${path.module}/../lambda/sns_publish_attributes"
  cloudwatch_logs_retention_in_days = 1
  timeout                           = 900
  attach_policy_json                = true
  policy_json                       = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "sns:Publish",
      "Resource": "${aws_sns_topic.network_manager_events.arn}"
    }
  ]
}
EOF
  environment_variables = {
    SNS_TOPIC_ARN = aws_sns_topic.network_manager_events.arn
  }
}

# AWS Native Events, no critical information present
resource "aws_sns_topic" "network_manager_events" {
  name                        = "networkmanager_events_${var.global_network_name}"
  kms_master_key_id           = "alias/aws/sns"
  fifo_topic                  = false
  content_based_deduplication = false
}

data "aws_iam_policy_document" "network_manager_events" {
  policy_id = "__default_policy_ID"
  statement {
    sid = "AllowPublish"
    actions = [
      "sns:Publish"
    ]
    effect = "Allow"
    resources = [
      aws_sns_topic.network_manager_events.arn
    ]
    principals {
      type        = "AWS"
      identifiers = [data.aws_caller_identity.current.account_id]
    }
  }
  statement {
    sid = "AllowSubscribe"
    actions = [
      "sns:Subscribe"
    ]
    effect = "Allow"
    resources = [
      aws_sns_topic.network_manager_events.arn
    ]
    principals {
      type        = "AWS"
      identifiers = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_sns_topic_policy" "network_manager_events" {
  arn    = aws_sns_topic.network_manager_events.arn
  policy = data.aws_iam_policy_document.network_manager_events.json
}

resource "aws_cloudwatch_event_rule" "network_manager_events" {
  name           = "networkmanager_events_${var.global_network_name}"
  event_bus_name = var.events_bus_name
  event_pattern  = <<EOF
{
  "source": ["aws.networkmanager"]
}
EOF
}

resource "aws_lambda_permission" "network_manager_events" {
  statement_id  = "AllowExecutionFromEvents"
  action        = "lambda:InvokeFunction"
  function_name = module.lambda_network_events_sns_publish.lambda_function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.network_manager_events.arn
}

resource "aws_cloudwatch_event_target" "network_manager_events" {
  rule = aws_cloudwatch_event_rule.network_manager_events.id
  arn  = module.lambda_network_events_sns_publish.lambda_function_arn
}



