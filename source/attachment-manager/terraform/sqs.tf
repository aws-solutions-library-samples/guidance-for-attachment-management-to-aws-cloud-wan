# Dead-letter queue (DLQ) for CloudWAN attachment events that have exhausted
# all retry attempts. Messages land here after maxReceiveCount=5 delivery
# failures on the main queue, providing an audit trail for attachments that
# could not be processed automatically.
resource "aws_sqs_queue" "cloudwan_tag_dlq" {
  name   = "${var.name}_dlq"
  region = data.aws_region.current.region

  fifo_queue                  = false
  content_based_deduplication = false

  # Server-side encryption with an SQS-managed key. No cross-account decryption
  # is needed, so a customer-managed KMS key is unnecessary.
  sqs_managed_sse_enabled = true
}

# Main queue that buffers CloudWAN attachment events between the SNS topic and
# the Lambda function.
resource "aws_sqs_queue" "cloudwan_tag" {
  name   = var.name
  region = data.aws_region.current.region

  # Optional initial delay before a message becomes visible. A non-zero value
  # can absorb transient Cloud WAN state-propagation delays at the cost of
  # higher end-to-end latency.
  delay_seconds = var.sqs_delay_seconds

  fifo_queue                  = false
  content_based_deduplication = false
  sqs_managed_sse_enabled     = true

  # visibility_timeout must be greater than the Lambda timeout (90 s) to prevent
  # a message from becoming visible again while the Lambda is still processing it.
  # 125 s provides sufficient headroom for slow Cloud WAN API responses.
  visibility_timeout_seconds = 125

  # After 5 failed delivery attempts (e.g. Lambda errors, or attachments that
  # never become ready) the message is moved to the DLQ for manual review.
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.cloudwan_tag_dlq.arn
    maxReceiveCount     = 5
  })
}

# Restricts writes to the queue so only the designated network-events SNS topic
# can send messages. This policy is separate from the Lambda execution role
# policy that governs reads.
resource "aws_sqs_queue_policy" "cloudwan_tag" {
  queue_url = aws_sqs_queue.cloudwan_tag.id
  region    = data.aws_region.current.region
  policy    = data.aws_iam_policy_document.sqs_cloudwan_tag.json
}
