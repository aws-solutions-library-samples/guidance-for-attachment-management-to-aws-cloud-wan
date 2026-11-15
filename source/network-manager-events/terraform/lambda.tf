# ─────────────────────────────────────────────────────────────────────────────
# Lambda — Network Events SNS Publisher
# ─────────────────────────────────────────────────────────────────────────────
#
# The Lambda function receives raw AWS Network Manager events from EventBridge,
# enriches them with structured SNS message attributes, and publishes the result
# to the SNS topic so that downstream consumers can filter by change type,
# attachment region, or core network ARN without deserialising the message body.
#
# Source: https://registry.terraform.io/modules/terraform-aws-modules/lambda/aws

#checkov:skip=CKV_TF_1:"Ensure Terraform module sources use a commit hash"
module "lambda_network_events_sns_publish" {
  source  = "terraform-aws-modules/lambda/aws"
  version = "8.8.0"

  # Pin to the explicitly provided region, or fall back to the provider default.
  region = var.region

  # Embed the global network name so multiple module instances in the same
  # account produce distinct function names.
  function_name = "network_events_sns_publish_${var.global_network_name}"

  # Handler path: <module_file>.<function_name> within the source directory.
  handler = "lambda_handler.handler"

  # Python runtime — configurable to allow upgrades without module changes.
  runtime = var.lambda_runtime

  # Path to the Lambda deployment source relative to this module root.
  source_path = "${path.module}/../lambda/sns_publish_attributes"

  # CloudWatch log retention mirrors the module-level variable.
  cloudwatch_logs_retention_in_days = var.cloudwatch_logs_retention_in_days

  # 15-minute ceiling — Network Manager events are low-volume; this upper bound
  # is intentionally generous to guard against transient SNS publish latency.
  timeout = 900

  # Attach the inline IAM policy granting sns:Publish on the topic created below.
  attach_policy_json = true
  policy_json        = data.aws_iam_policy_document.lambda_network_manager_events.json

  # Runtime configuration injected as environment variables.
  environment_variables = {
    # The SNS topic ARN that the handler publishes enriched events to.
    SNS_TOPIC_ARN = aws_sns_topic.network_manager_events.arn
    # Python logger verbosity level (WARN | INFO | DEBUG).
    LOGGING_LEVEL = var.lambda_logging_level
  }
}

# ─────────────────────────────────────────────────────────────────────────────
# EventBridge — Capture all aws.networkmanager source events
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_cloudwatch_event_rule" "network_manager_events" {
  # Scoped name prevents collisions when multiple module instances share
  # the same account and event bus.
  name   = "networkmanager_events_${var.global_network_name}"
  region = var.region

  # Subscribe to the configured event bus (default or custom).
  event_bus_name = var.events_bus_name

  # Broad match on the Network Manager source — the Lambda handler filters
  # event types (attachment created/deleted, route installed/removed) in code.
  event_pattern = jsonencode({
    source = ["aws.networkmanager"]
  })
}

# Grant EventBridge permission to invoke the Lambda function.
# source_arn restricts this permission to the specific rule above,
# preventing other EventBridge rules from invoking the function.
resource "aws_lambda_permission" "network_manager_events" {
  region        = var.region
  statement_id  = "AllowExecutionFromEvents"
  action        = "lambda:InvokeFunction"
  function_name = module.lambda_network_events_sns_publish.lambda_function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.network_manager_events.arn
}

# Wire the EventBridge rule to the Lambda function as its invocation target.
resource "aws_cloudwatch_event_target" "network_manager_events" {
  region = var.region
  rule   = aws_cloudwatch_event_rule.network_manager_events.id
  arn    = module.lambda_network_events_sns_publish.lambda_function_arn
}
