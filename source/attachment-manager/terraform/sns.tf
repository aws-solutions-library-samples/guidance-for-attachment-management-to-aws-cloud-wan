# Subscribes the SQS queue to the network-events SNS topic so that Cloud WAN
# attachment lifecycle events are buffered for Lambda processing.
#
# The aws.aws_sns_subscribe provider alias is used because the SNS topic may
# live in a different region from the Lambda and SQS queue (a common pattern
# in centralised-networking architectures where the Network Manager management
# plane is deployed in us-east-1 while workloads run in other regions).
resource "aws_sns_topic_subscription" "attachment_created" {
  provider = aws.aws_sns_subscribe
  region   = var.region_sns_topic_subscription

  topic_arn = var.network_events_sns_topic_arn
  protocol  = "sqs"
  endpoint  = aws_sqs_queue.cloudwan_tag.arn

  # Filter policy limits delivery to events for the specific core network managed
  # by this module instance. When core_network_arn is null no filter policy is set
  # and all events published to the topic are forwarded to the queue — useful
  # for single-core-network deployments where the topic carries only one network's
  # events.
  filter_policy = var.core_network_arn == null ? null : jsonencode({
    coreUplinkArn = [var.core_network_arn]
  })
}
