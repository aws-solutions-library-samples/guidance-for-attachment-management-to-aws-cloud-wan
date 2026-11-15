# The current AWS account ID is used to scope IAM policies and construct resource ARNs.
data "aws_caller_identity" "current" {}

# The current region (data.aws_region.current.region) is used to construct the Lambda
# function name ({name}_{region}_routing) and ensures resources are created in the
# intended region even when var.region is null.
data "aws_region" "current" {
  region = var.region
}
