# ─────────────────────────────────────────────────────────────────────────────
# SNS — Network Manager Events Topic
# ─────────────────────────────────────────────────────────────────────────────
#
# Standard (non-FIFO) topic encrypted with the AWS-managed SNS KMS key.
# Downstream subscribers filter events using SNS message attributes set by the
# Lambda handler:
#   coreNetworkArn   — ARN of the core network that generated the event
#   changeType       — API-level change type (e.g. VPC_ATTACHMENT_CREATED)
#   attachmentRegion — AWS region of the attachment edge location
#   coreUplinkArn    — ARN used for uplink correlation
#   attachmentArn    — ARN of the specific attachment (when present)

resource "aws_sns_topic" "network_manager_events" {
  # Use the explicit override when provided; otherwise derive the name from
  # the global network name to maintain consistent naming across the module.
  name   = var.sns_topic_name != null ? var.sns_topic_name : "networkmanager_events_${var.global_network_name}"
  region = var.region

  # Encrypt messages at rest using the AWS-managed SNS KMS key.
  # Switch to a customer-managed key ARN here if stricter key-rotation
  # policies or cross-account access are required.
  kms_master_key_id = "alias/aws/sns"

  # Standard topic — Network Manager events do not require strict FIFO ordering.
  fifo_topic = false

  # Content-based deduplication is only valid for FIFO topics; must be false here.
  content_based_deduplication = false
}

# Attach a resource policy granting the owning account permission to both
# publish messages and create subscriptions on this topic.
resource "aws_sns_topic_policy" "network_manager_events" {
  region = var.region
  arn    = aws_sns_topic.network_manager_events.arn
  policy = data.aws_iam_policy_document.sns_network_manager_events.json
}
