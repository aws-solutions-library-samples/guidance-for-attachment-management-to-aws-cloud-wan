# Instantiates the module under test.
# This file is used by the Python snapshot tests (test_terraform_snapshot.py),
# which run `tofu plan` from within the tests/ directory.
# It is NOT loaded when running `tofu test -test-directory=tests` from the repo root —
# those test scenarios are defined in the .tftest.hcl files.
# The SNS subscription provider alias is mapped to the default provider.
module "test_module" {
  providers                         = { aws.aws_sns_subscribe = aws }
  source                            = "../"
  name                              = "test"
  aws_account_reader_role_arn       = "arn:aws:iam::000000000000:role/org-reader"
  network_events_sns_topic_region   = "us-west-2"
  network_events_sns_topic_arn      = "arn:aws:sns:us-west-2:111111111111:network_manager_events"
  global_network_id                 = "global-network-123456789"
  core_network_arn                  = "arn:aws:networkmanager:us-east-1:111111111111:core-network/c0123456789abcdef"
  full_return_table                 = "fullreturn"
  cloudwatch_logs_retention_in_days = 1
  sqs_delay_seconds                 = 0
  ignore_aws_accounts               = []
  process_only_aws_accounts         = []
  vpc_segment_address_map = {
    prod = {
      "eu-west-1" = ["10.0.0.0/16"],
      "eu-west-2" = ["10.1.0.0/16"],
    }
    nonprod = {
      "eu-west-1" = ["10.2.0.0/16"],
      "eu-west-2" = ["10.3.0.0/16"],
    }
  }
}

# Regional inspection segments only: every region had its last-hop loopback
# removed, so there is no global full return segment. Conflicting routes are
# checked in the inspection segment of each edge. No address map, so this
# instance writes no vpc_segment_address_map.yml.
module "test_module_regional" {
  providers                         = { aws.aws_sns_subscribe = aws }
  source                            = "../"
  name                              = "test-regional"
  aws_account_reader_role_arn       = "arn:aws:iam::000000000000:role/org-reader"
  network_events_sns_topic_region   = "us-west-2"
  network_events_sns_topic_arn      = "arn:aws:sns:us-west-2:111111111111:network_manager_events"
  global_network_id                 = "global-network-123456789"
  core_network_arn                  = "arn:aws:networkmanager:us-east-1:111111111111:core-network/c0123456789abcdef"
  full_return_table                 = ""
  cloudwatch_logs_retention_in_days = 1
  lambda_sqs_maximum_concurrency    = 2
  full_return_table_by_region = {
    "eu-west-1" = "inspectioneuw1"
    "eu-west-2" = "inspectioneuw2"
  }
}
