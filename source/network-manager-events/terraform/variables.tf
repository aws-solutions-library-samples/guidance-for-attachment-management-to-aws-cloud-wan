# ─────────────────────────────────────────────────────────────────────────────
# Input variables
# ─────────────────────────────────────────────────────────────────────────────

variable "global_network_name" {
  description = "Human-readable name for the AWS Network Manager Global Network. Embedded as a suffix in all derived resource names (SNS topic, EventBridge rule, Lambda function) to keep resources identifiable and avoid collisions when multiple instances of this module share the same account."
  type        = string
}

variable "events_bus_name" {
  description = "Name of the EventBridge event bus that the Network Manager event rule subscribes to. AWS Network Manager publishes events to the account-default bus; override this only when routing events via a custom or cross-account bus."
  type        = string
  default     = "default"
}

variable "cloudwatch_logs_retention_in_days" {
  description = "Number of days to retain Lambda function log events in CloudWatch Logs. Set to 0 for indefinite retention (not recommended for cost control)."
  type        = number
  default     = 30
}

variable "lambda_logging_level" {
  description = "Logging verbosity for the Lambda event processor, passed as the LOGGING_LEVEL environment variable. WARN is appropriate for production. INFO or DEBUG produce significant additional volume and should only be used during active troubleshooting."
  type        = string
  default     = "WARN"

  validation {
    condition     = contains(["WARN", "INFO", "DEBUG"], var.lambda_logging_level)
    error_message = "The lambda_logging_level must be one of 'WARN', 'INFO', 'DEBUG'."
  }
}

variable "sns_topic_name" {
  description = "Override the SNS topic name. When null the name is auto-generated as 'networkmanager_events_<global_network_name>'. Set this only when integrating with an existing fixed topic name that downstream subscribers are already configured against."
  type        = string
  default     = null
}

variable "region" {
  description = "AWS region in which the resources are created. Defaults to the region of the configured AWS provider when null. Set explicitly when the module is called from a configuration that uses provider aliases."
  type        = string
  default     = null
}

variable "lambda_runtime" {
  description = "Python runtime identifier for the Lambda function (e.g. python3.14). Defaults to python3.14. Advance this only after validating the handler code against the new interpreter."
  type        = string
  default     = "python3.14"
}
