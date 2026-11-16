# Declares the minimum Terraform/OpenTofu version constraints and required
# provider configurations for this module.
terraform {
  # mock_provider in the .tftest.hcl files needs OpenTofu >= 1.8.
  required_version = ">= 1.8"

  required_providers {
    # AWS provider manages all Cloud WAN, Lambda, SQS, SNS, and IAM resources.
    aws = {
      source                = "hashicorp/aws"
      version               = "~> 6.0"
      configuration_aliases = [aws.aws_sns_subscribe]
    }
    # Local provider is used to write the vpc_segment_address_map YAML file
    # into the Lambda source directory before packaging.
    local = {
      source  = "hashicorp/local"
      version = "~> 2.0"
    }
  }
}
