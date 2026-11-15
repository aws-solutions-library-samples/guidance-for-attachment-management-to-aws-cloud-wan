# ─────────────────────────────────────────────────────────────────────────────
# Provider and version constraints
# ─────────────────────────────────────────────────────────────────────────────
#
# Declares the minimum OpenTofu / Terraform version constraints and the
# required provider configurations for this module.

terraform {
  required_providers {
    # The AWS provider manages all resources created by this module:
    # Network Manager, Lambda, SNS, EventBridge, IAM, and CloudWatch Logs.
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}
