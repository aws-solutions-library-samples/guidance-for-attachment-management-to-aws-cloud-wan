# CloudWatch alarm that fires when messages arrive in the dead-letter queue,
# indicating CloudWAN attachment events that exhausted all retry attempts.

resource "aws_cloudwatch_metric_alarm" "dlq_messages" {
  count = var.dlq_alarm_enabled ? 1 : 0

  region              = data.aws_region.current.region
  alarm_name          = "${var.name}_dlq_messages"
  alarm_description   = "Alarm when messages arrive in the ${var.name} dead-letter queue, indicating CloudWAN attachment events that failed all retry attempts."
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 300
  statistic           = "Maximum"
  threshold           = var.dlq_alarm_threshold
  treat_missing_data  = "notBreaching"

  dimensions = {
    QueueName = aws_sqs_queue.cloudwan_tag_dlq.name
  }

  alarm_actions = var.dlq_alarm_sns_topic_arn != null ? [var.dlq_alarm_sns_topic_arn] : []
  ok_actions    = var.dlq_alarm_sns_topic_arn != null ? [var.dlq_alarm_sns_topic_arn] : []
}
