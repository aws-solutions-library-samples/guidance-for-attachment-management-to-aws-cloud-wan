# ─────────────────────────────────────────────────────────────────────────────
# Outputs — expose key identifiers for downstream Terraform configurations
# ─────────────────────────────────────────────────────────────────────────────

output "global_network_id" {
  description = "The ID of the AWS Network Manager Global Network created by this module. Reference this from core-network or attachment modules."
  value       = aws_networkmanager_global_network.global_network.id
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic that receives enriched Network Manager change events. Use this to create SQS, Lambda, or HTTP subscriptions in consuming modules."
  value       = aws_sns_topic.network_manager_events.arn
}

output "region_name" {
  description = "AWS region in which this module's resources were deployed."
  value       = data.aws_region.current.region
}

output "lambda_destination_on_failure_arn" {
  description = "Destination of the failed asynchronous invocations of the publisher Lambda, or null."
  value       = var.lambda_destination_on_failure_arn
}

output "lambda_timeout" {
  description = "Timeout in seconds of the publisher Lambda function."
  value       = local.lambda_timeout
}
