terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = "eu-west-1"
}

provider "aws" {
  region = "eu-west-1"
  alias  = "aws_sns_subscribe"
}
