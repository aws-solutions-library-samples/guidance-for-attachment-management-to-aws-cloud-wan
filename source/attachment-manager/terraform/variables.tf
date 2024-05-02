variable "name" {
  description = "Name of the Attachment Manager objects"
  type        = string
}

variable "aws_account_reader_role_arn" {
  description = "ARN of the Management Account role to allow reading the AWS Organization Structure"
  type        = string
}

variable "network_events_sns_topic_region" {
  description = "Region of the topic containing curated events from Network Manager"
  type        = string
  default     = "us-west-2"
}

variable "network_events_sns_topic_arn" {
  description = "ARN of the topic containing curated events from Network Manager"
  type        = string
}

variable "global_network_id" {
  description = "Network Manager Global Network Id to verity management objects"
  type        = string
  default     = null
}

variable "core_network_arn" {
  description = "CloudWAN Core Network ARN to manage"
  type        = string
  default     = null
}

variable "tgw_arn" {
  description = "Transit Gateway ARN to manage"
  type        = string
  default     = null
}

variable "lambda_routing_config_local_package" {
  description = "Optimization to re-use local binaries when deploying the lambda to several regions"
  type        = string
  default     = null
}

variable "vpc_segment_address_map" {
  description = "Object containing hierarchy of regions and segments with the accepted lists of IP Address summaries"
  type        = map(any)
  default     = null
}

variable "sqs_delay_seconds" {
  description = "SQS delay between receiving a message, and allowing it to be visible for processing"
  type        = number
  default     = 0
}

variable "ignore_aws_accounts" {
  description = "AWS accounts identifiers which the solution should ignore"
  type        = list(string)
  default     = []
}

variable "process_only_aws_accounts" {
  description = "AWS accounts identifiers which the solution should only process"
  type        = list(string)
  default     = []
}

variable "lambda_perform_attachment_deletion" {
  description = "Allow lambda to perform attachment deletions"
  type        = bool
  default     = true
}

variable "full_return_table" {
  description = "Full return table containing every known network route"
  type        = string
}

variable "sns_monitoring_topic_arn" {
  description = "Optional SNS topic to publish interesting events from an operations perspective."
  type        = string
  default     = ""
}

variable "sns_monitoring_topic_region" {
  description = "Optional Region of SNS topic to publish interesting events from an operations perspective."
  type        = string
  default     = ""
}