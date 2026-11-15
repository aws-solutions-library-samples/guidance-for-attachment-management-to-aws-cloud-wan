# ─── Lambda ───────────────────────────────────────────────────────────────────

output "lambda_routing_config_local_package" {
  description = "Local path of the built Lambda deployment package. Pass this value as lambda_routing_config_local_package when promoting the same artefact to a subsequent environment."
  value       = module.lambda_routing_config_on_demand.local_filename
}

output "lambda_function_name" {
  description = "Name of the CloudWAN routing configuration Lambda function ({name}_{region}_routing)."
  value       = module.lambda_routing_config_on_demand.lambda_function_name
}

output "lambda_function_arn" {
  description = "ARN of the CloudWAN routing configuration Lambda function."
  value       = module.lambda_routing_config_on_demand.lambda_function_arn
}

# ─── SQS ──────────────────────────────────────────────────────────────────────

output "sqs_queue_name" {
  description = "Name of the main SQS queue that buffers CloudWAN attachment events."
  value       = aws_sqs_queue.cloudwan_tag.name
}

output "sqs_queue_arn" {
  description = "ARN of the main SQS queue."
  value       = aws_sqs_queue.cloudwan_tag.arn
}

output "sqs_queue_url" {
  description = "URL of the main SQS queue (also set as the SQS_URL Lambda environment variable)."
  value       = aws_sqs_queue.cloudwan_tag.url
}

output "sqs_queue_visibility_timeout_seconds" {
  description = "SQS visibility timeout in seconds. Must exceed the Lambda timeout (90 s) to prevent duplicate processing."
  value       = aws_sqs_queue.cloudwan_tag.visibility_timeout_seconds
}

output "sqs_queue_delay_seconds" {
  description = "Seconds a message is delayed before becoming visible to consumers."
  value       = aws_sqs_queue.cloudwan_tag.delay_seconds
}

output "sqs_dlq_name" {
  description = "Name of the dead-letter queue for attachment events that exhausted all retry attempts."
  value       = aws_sqs_queue.cloudwan_tag_dlq.name
}

output "sqs_dlq_arn" {
  description = "ARN of the dead-letter queue."
  value       = aws_sqs_queue.cloudwan_tag_dlq.arn
}

output "sqs_max_receive_count" {
  description = "Number of times a message is delivered before being sent to the DLQ (derived from the redrive policy)."
  value       = jsondecode(aws_sqs_queue.cloudwan_tag.redrive_policy).maxReceiveCount
}

# ─── SNS ──────────────────────────────────────────────────────────────────────

output "sns_subscription_arn" {
  description = "ARN of the SNS subscription that connects the network-events topic to the SQS queue."
  value       = aws_sns_topic_subscription.attachment_created.arn
}

output "sns_filter_policy" {
  description = "JSON filter policy applied to the SNS subscription, restricting events to the managed core network (coreUplinkArn). Null when core_network_arn is not set."
  value       = aws_sns_topic_subscription.attachment_created.filter_policy
}

# ─── Lambda Environment Variable Mirrors ──────────────────────────────────────
# These outputs expose the values that were written to Lambda environment variables.
# They are primarily useful for test assertions and for auditing the deployed configuration.

output "lambda_env_perform_deletions" {
  description = "Value of the PERFORM_ATTACHMENT_DELETIONS Lambda environment variable ('true' or 'false')."
  value       = tostring(var.lambda_perform_attachment_deletion)
}

output "lambda_env_logging_level" {
  description = "Value of the LOGGING_LEVEL Lambda environment variable."
  value       = var.lambda_logging_level
}

output "lambda_env_segment_addressing_file" {
  description = "Value of the SEGMENT_ADDRESSING_FILE Lambda environment variable. Empty string when vpc_segment_address_map is not provided."
  value       = var.vpc_segment_address_map == null ? "" : "vpc_segment_address_map.yml"
}

output "lambda_env_ignore_accounts" {
  description = "JSON-encoded value of the IGNORE_AWS_ACCOUNTS Lambda environment variable."
  value       = jsonencode(var.ignore_aws_accounts)
}

output "lambda_env_process_only_accounts" {
  description = "JSON-encoded value of the PROCESS_ONLY_AWS_ACCOUNTS Lambda environment variable."
  value       = jsonencode(var.process_only_aws_accounts)
}

output "lambda_env_full_return_table" {
  description = "Value of the FULL_RETURN_TABLE Lambda environment variable."
  value       = var.full_return_table == null ? "" : var.full_return_table
}

output "lambda_env_full_return_table_by_region" {
  description = "JSON-encoded value of the FULL_RETURN_TABLE_BY_REGION Lambda environment variable."
  value       = jsonencode(var.full_return_table_by_region)
}

# ─── DLQ Alarm ────────────────────────────────────────────────────────────────

output "dlq_alarm_arn" {
  description = "ARN of the CloudWatch alarm monitoring the DLQ, or null if disabled."
  value       = var.dlq_alarm_enabled ? aws_cloudwatch_metric_alarm.dlq_messages[0].arn : null
}
