# ─── Naming & Region ──────────────────────────────────────────────────────────

variable "name" {
  description = "Base name applied to all resources created by this module (SQS queues, Lambda function)."
  type        = string
  validation {
    condition     = length(var.name) >= 1 && length(var.name) <= 80 && can(regex("^[a-zA-Z0-9_-]+$", var.name))
    error_message = "name must be 1-80 characters and contain only alphanumerics, hyphens, and underscores."
  }
}

variable "region" {
  description = "AWS region in which SQS queues and the Lambda function are created. Defaults to the region of the configured AWS provider."
  type        = string
  default     = null
}

# ─── SNS Topic (Network Events Source) ────────────────────────────────────────

variable "network_events_sns_topic_region" {
  description = "AWS region where the network-events SNS topic lives. Used when the topic is in a different region from the Lambda (common in centralised-networking designs)."
  type        = string
}

variable "network_events_sns_topic_arn" {
  description = "ARN of the SNS topic that publishes Cloud WAN attachment lifecycle events. The module subscribes an SQS queue to this topic."
  type        = string
}

variable "region_sns_topic_subscription" {
  description = "Region passed to the aliased aws.aws_sns_subscribe provider when creating the SNS subscription. Must match network_events_sns_topic_region when the topic is cross-region."
  type        = string
  default     = null
}

# ─── Cloud WAN Core Network ────────────────────────────────────────────────────

variable "core_network_arn" {
  description = "ARN of the Cloud WAN core network managed by this module. When set, the SNS subscription filter policy restricts events to attachments belonging to this core network. When null, all attachment events from the topic are forwarded."
  type        = string
  default     = null
}

variable "global_network_id" {
  description = "Network Manager global network ID. Passed to the Lambda as MANAGED_GLOBAL_NETWORK_ID; required for NetworkManager API calls that operate at global-network scope."
  type        = string
}

# ─── Routing Policy / Segment Addressing ──────────────────────────────────────

variable "vpc_segment_address_map" {
  description = <<-EOT
    Map of segment name → region → list of CIDR prefixes that define valid address ranges for each segment.
    When provided, the Lambda validates that an attaching VPC's CIDR falls within the expected range for
    its target segment. When null, IP-range validation is skipped and SEGMENT_ADDRESSING_FILE is left empty.

    Example:
      vpc_segment_address_map = {
        prod    = { "eu-west-1" = ["10.0.0.0/16"], "eu-west-2" = ["10.1.0.0/16"] }
        nonprod = { "eu-west-1" = ["10.2.0.0/16"], "eu-west-2" = ["10.3.0.0/16"] }
      }
  EOT
  type        = map(any)
  default     = null
  validation {
    condition     = var.vpc_segment_address_map == null ? true : alltrue([for segment in keys(var.vpc_segment_address_map) : can(regex("^[A-Za-z0-9]+$", segment))])
    error_message = "vpc_segment_address_map segment names must only contain letters and numbers."
  }
}

variable "full_return_table" {
  description = "Name of the Cloud WAN segment that contains the full set of known network routes (e.g. the last-hop loopback return segment). The Lambda queries this segment to detect overlapping CIDRs before accepting a new VPC attachment. Empty string disables conflict detection for regions not listed in full_return_table_by_region."
  type        = string
  default     = ""
  validation {
    condition     = var.full_return_table == null ? true : can(regex("^[A-Za-z0-9]*$", var.full_return_table))
    error_message = "full_return_table must only contain letters and numbers."
  }
}

variable "full_return_table_by_region" {
  description = <<-EOT
    Map of AWS region name → Cloud WAN segment that contains the full set of known network routes for that
    edge location. Takes precedence over full_return_table for the listed regions. Use it when the last-hop
    loopback has been removed for a region and its regional inspection segment learns every attachment route,
    e.g. {"eu-west-1" = "inspectioneuw1"}. Regions with and without loopbacks can be mixed.
  EOT
  type        = map(string)
  default     = {}
  validation {
    condition     = alltrue([for segment in values(var.full_return_table_by_region) : can(regex("^[A-Za-z0-9]+$", segment))])
    error_message = "full_return_table_by_region segment names must only contain letters and numbers."
  }
}

variable "cloudwan_route_domain_tag" {
  description = "Name of the AWS Organizations account tag that the Lambda reads to determine which Cloud WAN routing segment (domain) an account's VPC attachments should be placed in. The tag value must match a segment name in the core network policy."
  type        = string
  default     = "route-domain"
}

variable "cloudwan_quarantine_table" {
  description = "Name of the Cloud WAN segment used to isolate non-compliant VPC attachments. Attachments that fail validation (wrong CIDR, missing org tag) are tagged to this segment instead of being deleted when lambda_perform_attachment_deletion is false."
  type        = string
  default     = "quarantine"
  validation {
    condition     = can(regex("^[A-Za-z0-9]+$", var.cloudwan_quarantine_table))
    error_message = "cloudwan_quarantine_table must only contain letters and numbers."
  }
}

variable "cloudwan_quarantineroutes_table" {
  description = "Name of the Cloud WAN segment used for quarantined attachment route learning. Routes from quarantined attachments are propagated here so operators can inspect them without affecting production routing tables."
  type        = string
  default     = "quarantineroutes"
  validation {
    condition     = can(regex("^[A-Za-z0-9]+$", var.cloudwan_quarantineroutes_table))
    error_message = "cloudwan_quarantineroutes_table must only contain letters and numbers."
  }
}

# ─── Account Filtering ─────────────────────────────────────────────────────────

variable "ignore_aws_accounts" {
  description = "List of AWS account IDs whose VPC attachment events should be silently ignored. Takes precedence over process_only_aws_accounts when both are set."
  type        = list(string)
  default     = []
}

variable "process_only_aws_accounts" {
  description = "Allowlist of AWS account IDs to process. When non-empty, the Lambda skips attachment events from any account not in this list. Useful for phased roll-outs."
  type        = list(string)
  default     = []
}

# ─── Lambda Configuration ──────────────────────────────────────────────────────

variable "lambda_runtime" {
  description = "Python runtime identifier for the Lambda function. Defaults to python3.14."
  type        = string
  default     = "python3.14"
}

variable "lambda_routing_config_local_package" {
  description = "Path to a pre-built Lambda deployment package (.zip). When provided, the module skips building the package from source and deploys this file directly. Useful for promoting the same artefact across environments."
  type        = string
  default     = null
}

variable "lambda_perform_attachment_deletion" {
  description = "Allow the Lambda to delete non-compliant VPC attachments. When false, non-compliant attachments are moved to the quarantine segment instead of being deleted — useful during initial roll-out or troubleshooting."
  type        = bool
  default     = true
}

variable "lambda_logging_level" {
  description = "Logging verbosity for the Lambda function. WARN is suitable for production; INFO adds per-attachment decisions; DEBUG includes full API payloads."
  type        = string
  default     = "WARN"
  validation {
    condition     = contains(["WARN", "INFO", "DEBUG"], var.lambda_logging_level)
    error_message = "The lambda_logging_level must be one of 'WARN', 'INFO', 'DEBUG'."
  }
}

variable "aws_account_reader_role_arn" {
  description = "ARN of the cross-account IAM role the Lambda assumes to read AWS Organizations account tags. The role must exist in the Organizations management account (or a delegated admin) and allow sts:AssumeRole from the Lambda's execution role."
  type        = string
  validation {
    condition     = can(regex("^arn:aws:iam::[0-9]{12}:role/.+$", var.aws_account_reader_role_arn))
    error_message = "aws_account_reader_role_arn must be a valid IAM role ARN (arn:aws:iam::<account-id>:role/<name>)."
  }
}

variable "lambda_reserved_concurrent_executions" {
  description = "Maximum number of concurrent Lambda invocations. Set to null for unlimited. A low value (e.g. 1) ensures sequential processing which avoids race conditions on attachment state."
  type        = number
  default     = null
}

# ─── Operational ──────────────────────────────────────────────────────────────

variable "cloudwatch_logs_retention_in_days" {
  description = "Number of days to retain Lambda CloudWatch log events. Set to a lower value (e.g. 7) in development environments and higher (e.g. 90) in production for compliance."
  type        = number
  default     = 30
  validation {
    condition = contains(
      [0, 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653],
      var.cloudwatch_logs_retention_in_days
    )
    error_message = "cloudwatch_logs_retention_in_days must be one of the values accepted by AWS: 0, 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653."
  }
}

variable "sqs_delay_seconds" {
  description = "Delay in seconds before a message delivered to the SQS queue becomes visible to the Lambda. A non-zero value can absorb transient Cloud WAN state-propagation delays."
  type        = number
  default     = 0
  validation {
    condition     = var.sqs_delay_seconds >= 0 && var.sqs_delay_seconds <= 900
    error_message = "sqs_delay_seconds must be between 0 and 900 (AWS maximum)."
  }
}

# ─── DLQ Alarm ────────────────────────────────────────────────────────────────

variable "dlq_alarm_enabled" {
  description = "Whether to create a CloudWatch alarm for messages arriving in the dead-letter queue."
  type        = bool
  default     = true
}

variable "dlq_alarm_sns_topic_arn" {
  description = "ARN of an SNS topic to notify when the DLQ alarm fires. When null, the alarm is created but sends no notifications."
  type        = string
  default     = null
}

variable "dlq_alarm_threshold" {
  description = "Number of messages in the DLQ that triggers the alarm."
  type        = number
  default     = 1
}
