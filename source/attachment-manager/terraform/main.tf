# Business logic...

# Get account id
data "aws_caller_identity" "current" {}


# Get region
data "aws_region" "current" {}


resource "aws_sqs_queue" "cloudwan_tag_dlq" {
  name                        = "${var.name}_dlq"
  fifo_queue                  = false
  content_based_deduplication = false
  sqs_managed_sse_enabled     = true
}
resource "aws_sqs_queue" "cloudwan_tag" {
  name                        = var.name
  delay_seconds               = var.sqs_delay_seconds
  fifo_queue                  = false
  content_based_deduplication = false
  sqs_managed_sse_enabled     = true
  visibility_timeout_seconds  = 95
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.cloudwan_tag_dlq.arn
    maxReceiveCount     = 3
  })
}
resource "aws_sqs_queue_policy" "cloudwan_tag" {
  queue_url = aws_sqs_queue.cloudwan_tag.id
  policy    = <<POLICY
{
  "Version": "2012-10-17",
  "Id": "sqspolicy",
  "Statement": [
    {
      "Sid": "First",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "sqs:SendMessage",
      "Resource": "${aws_sqs_queue.cloudwan_tag.arn}",
      "Condition": {
        "ArnEquals": {
          "aws:SourceArn": "${var.network_events_sns_topic_arn}"
        }
      }
    }
  ]
}
POLICY
}



# Lambda: Routing Configuration
# https://registry.terraform.io/modules/terraform-aws-modules/lambda/aws/latest
module "lambda_routing_config_on_demand" {
  source        = "terraform-aws-modules/lambda/aws"
  function_name = "${var.name}_${data.aws_region.current.name}_routing"
  handler       = "lambda_handler.handler"
  runtime       = "python3.9"
  # publish            = true
  # recreate_missing_package = false
  source_path                       = "${path.module}/../lambda/attachment_manager"
  cloudwatch_logs_retention_in_days = 1
  memory_size                       = 128
  timeout                           = 90
  attach_policy_json                = true
  local_existing_package            = var.lambda_routing_config_local_package == null ? null : var.lambda_routing_config_local_package
  hash_extra                        = "${var.name}_${data.aws_region.current.name}_attachment_manager" # https://github.com/terraform-aws-modules/terraform-aws-lambda/issues/204
  policy_json                       = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "networkmanager:Get*",
        "networkmanager:List*",
        "networkmanager:DeleteAttachment",
        "networkmanager:TagResource",
        "networkmanager:GetNetworkRoutes",
        "ec2:DescribeRegions"
      ],
      "Resource": ["*"]
    },
    {
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "${var.aws_account_reader_role_arn}"
    },
    {
      "Effect": "Allow",
      "Action": [
        "sqs:ReceiveMessage",
        "sqs:SendMessage",
        "sqs:DeleteMessage",
        "sqs:GetQueueAttributes"
      ],
      "Resource": "${aws_sqs_queue.cloudwan_tag.arn}"
    },
    {
      "Effect": "Allow",
      "Action": [
        "sns:Publish"
      ],
      "Resource": "*"
    }
  ]
}
EOF
  environment_variables = {
    AWS_ACCOUNT_READ_ROLE_ARN    = var.aws_account_reader_role_arn
    MANAGED_CORE_NETWORK_ARN     = var.core_network_arn == null ? "" : var.core_network_arn
    MANAGED_GLOBAL_NETWORK_ID    = var.global_network_id == null ? "" : var.global_network_id
    MANAGED_TGW_ARN              = var.tgw_arn == null ? "" : var.tgw_arn
    FULL_RETURN_TABLE            = var.full_return_table == null ? "" : var.full_return_table
    SQS_URL                      = aws_sqs_queue.cloudwan_tag.url
    SEGMENT_ADDRESSING_FILE      = var.vpc_segment_address_map == null ? "" : "vpc_segment_address_map.yml"
    IGNORE_AWS_ACCOUNTS          = jsonencode(var.ignore_aws_accounts)
    PROCESS_ONLY_AWS_ACCOUNTS    = jsonencode(var.process_only_aws_accounts)
    PERFORM_ATTACHMENT_DELETIONS = tostring(var.lambda_perform_attachment_deletion)
    SNS_TOPIC_ARN                = var.sns_monitoring_topic_arn
    SNS_TOPIC_REGION             = var.sns_monitoring_topic_region
  }
  depends_on = [
    local_file.vpc_segment_address_map
  ]
}
resource "local_file" "vpc_segment_address_map" {
  count    = var.vpc_segment_address_map == null ? 0 : 1
  filename = "${path.module}/lambda/routing_config/vpc_segment_address_map.yml"
  content  = yamlencode(var.vpc_segment_address_map)
}



# Allow Lambda to read sqs
resource "aws_lambda_permission" "allow_sqs" {
  statement_id  = "AllowExecutionFromSQS"
  action        = "lambda:InvokeFunction"
  function_name = module.lambda_routing_config_on_demand.lambda_function_arn
  principal     = "sqs.amazonaws.com"
  source_arn    = aws_sqs_queue.cloudwan_tag.arn
}
resource "aws_lambda_event_source_mapping" "attachment_created" {
  event_source_arn = aws_sqs_queue.cloudwan_tag.arn
  function_name    = module.lambda_routing_config_on_demand.lambda_function_arn
}
resource "aws_sns_topic_subscription" "attachment_created" {
  provider  = aws.aws_sns_subscribe # aws.sns_topic_provider
  topic_arn = var.network_events_sns_topic_arn
  protocol  = "sqs"
  endpoint  = aws_sqs_queue.cloudwan_tag.arn
  filter_policy = jsonencode({
    coreUplinkArn = concat(
      var.core_network_arn == null ? [] : [var.core_network_arn],
      var.tgw_arn == null ? [] : [var.tgw_arn]
    )
  })
}
