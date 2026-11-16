# ─────────────────────────────────────────────────────────────────────────────
# AWS Network Manager — Global Network
# ─────────────────────────────────────────────────────────────────────────────
#
# IMPORTANT: After the Global Network is created you must manually enable
# Network Manager Event monitoring on the associated core network so that
# topology changes (attachment creation, route installation, etc.) are emitted
# to EventBridge. Without this step the EventBridge rule created in lambda.tf
# will never fire.
#
# Enable via the AWS Console or CLI:
# https://docs.aws.amazon.com/vpc/latest/tgwnm/monitoring-events.html

# Network Manager (global service, home region us-west-2) only publishes its
# EventBridge events in us-west-2. Elsewhere the rule in lambda.tf never fires.
check "network_manager_events_region" {
  assert {
    condition     = data.aws_region.current.region == "us-west-2"
    error_message = "Network Manager publishes its EventBridge events in us-west-2 only. This module is deployed in ${data.aws_region.current.region}, so the EventBridge rule will never fire."
  }
}

resource "aws_networkmanager_global_network" "global_network" {
  # The Name tag is the human-readable identifier surfaced in the AWS Console.
  # It is also used as the naming suffix for all resources derived from this
  # module (SNS topic, EventBridge rule, Lambda function).
  tags = {
    Name = var.global_network_name
  }
}
