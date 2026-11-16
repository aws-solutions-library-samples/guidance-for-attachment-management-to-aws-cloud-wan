# Lambda function that processes Cloud WAN attachment events.
# Sourced from the community terraform-aws-modules/lambda module which handles
# packaging, role creation, and CloudWatch log group provisioning.
# https://registry.terraform.io/modules/terraform-aws-modules/lambda/aws/latest
module "lambda_routing_config_on_demand" {
  source  = "terraform-aws-modules/lambda/aws"
  version = "8.8.0"

  region = data.aws_region.current.region

  # Function name follows the convention {name}_{region}_routing, enabling
  # multiple module instances (one per core network / region pair) to coexist
  # in the same AWS account without naming conflicts.
  function_name = "${var.name}_${data.aws_region.current.region}_routing"
  handler       = "lambda_handler.handler"
  runtime       = var.lambda_runtime

  # Source directory is packaged on first deploy. Pass lambda_routing_config_local_package
  # to skip packaging and deploy a pre-built artefact (e.g. for environment promotion).
  # The address map is generated per module instance (outside the shared module
  # directory) and added to the root of the package.
  source_path = concat(
    # pip_requirements must be explicit with the map form (the string form detects
    # requirements.txt automatically): pyyaml isn't part of the Lambda runtime.
    [{ path = "${path.module}/../lambda/attachment_manager", pip_requirements = true }],
    var.vpc_segment_address_map == null ? [] : [{ path = local.address_map_dir }],
  )
  local_existing_package = var.lambda_routing_config_local_package == null ? null : var.lambda_routing_config_local_package

  # hash_extra ensures a unique content hash when the same source directory is
  # deployed to multiple regions or under different names in the same workspace.
  hash_extra = "${var.name}_${data.aws_region.current.region}_routing_on_demand"

  cloudwatch_logs_retention_in_days = var.cloudwatch_logs_retention_in_days

  reserved_concurrent_executions = var.lambda_reserved_concurrent_executions

  # 128 MB is sufficient for a Python function that calls AWS APIs sequentially.
  memory_size = 128

  # 90 s covers slow Cloud WAN API responses. The SQS visibility timeout (125 s)
  # is set higher so the message stays hidden while the function is running, and
  # doubles as the back-off before an attachment that is not ready is retried.
  timeout = 90

  attach_policy_json = true
  policy_json        = data.aws_iam_policy_document.lambda_routing_config_on_demand.json

  environment_variables = {
    # Cross-account role for reading the "route-domain" tag from AWS Organizations.
    AWS_ACCOUNT_READ_ROLE_ARN = var.aws_account_reader_role_arn

    # Core network managed by this instance (informational; events are filtered by the SNS subscription).
    MANAGED_CORE_NETWORK_ARN = var.core_network_arn == null ? "" : var.core_network_arn

    # Required by NetworkManager API calls that are scoped to a global network.
    MANAGED_GLOBAL_NETWORK_ID = var.global_network_id

    # Segment name to query when checking for overlapping CIDRs.
    # Empty string disables the overlap-detection feature (unless set per region).
    FULL_RETURN_TABLE = var.full_return_table == null ? "" : var.full_return_table

    # JSON map of region → segment name for region-specific overlap checks
    # (e.g. regional inspection segments when the last-hop loopback is removed).
    FULL_RETURN_TABLE_BY_REGION = jsonencode(var.full_return_table_by_region)

    # Path to the YAML address map inside the Lambda package.
    # Empty string when vpc_segment_address_map is not provided (IP validation disabled).
    SEGMENT_ADDRESSING_FILE = var.vpc_segment_address_map == null ? "" : "vpc_segment_address_map.yml"

    # JSON-encoded lists for per-account allow/deny filtering.
    IGNORE_AWS_ACCOUNTS       = jsonencode(var.ignore_aws_accounts)
    PROCESS_ONLY_AWS_ACCOUNTS = jsonencode(var.process_only_aws_accounts)

    # When "false", non-compliant attachments are quarantined rather than deleted.
    PERFORM_ATTACHMENT_DELETIONS = tostring(var.lambda_perform_attachment_deletion)

    LOGGING_LEVEL = var.lambda_logging_level

    # AWS Organizations account tag name to retrieve the Cloud WAN routing domain
    ACCOUNT_ROUTE_DOMAIN_TAG = var.cloudwan_route_domain_tag

    # Cloud WAN segment for attachment quarantine
    QUARANTINE_SEGMENT = var.cloudwan_quarantine_table

    # Cloud WAN segment for attachment quarantine route learning
    QUARANTINE_ROUTES_SEGMENT = var.cloudwan_quarantineroutes_table
  }

  # The vpc_segment_address_map YAML file must exist inside the Lambda package
  # directory before the packaging step runs.
  depends_on = [local_file.vpc_segment_address_map]
}

locals {
  # One directory per module instance, so that several instances (e.g. a primary
  # and a secondary region) never share, overwrite or delete each other's map.
  address_map_dir = "${path.root}/builds/${var.name}_${data.aws_region.current.region}_address_map"
}

# When vpc_segment_address_map is provided, serialize it as YAML into the
# instance directory, which is bundled at the root of the deployment package.
# The file name matches the SEGMENT_ADDRESSING_FILE environment variable above.
resource "local_file" "vpc_segment_address_map" {
  count           = var.vpc_segment_address_map == null ? 0 : 1
  filename        = "${local.address_map_dir}/vpc_segment_address_map.yml"
  content         = yamlencode(var.vpc_segment_address_map)
  file_permission = "0644"
}

# Event source mapping that polls the SQS queue and invokes the Lambda
# automatically when messages are available. SQS handles long-polling,
# batching, and visibility management. The mapping polls with the Lambda
# execution role, so no resource-based invoke permission is needed.
resource "aws_lambda_event_source_mapping" "attachment_created" {
  region                  = data.aws_region.current.region
  event_source_arn        = aws_sqs_queue.cloudwan_tag.arn
  function_name           = module.lambda_routing_config_on_demand.lambda_function_arn
  function_response_types = ["ReportBatchItemFailures"]

  # Limits concurrency at the poller instead of throttling the function: throttled
  # receives would count towards maxReceiveCount and move messages to the DLQ.
  dynamic "scaling_config" {
    for_each = var.lambda_sqs_maximum_concurrency == null ? [] : [var.lambda_sqs_maximum_concurrency]
    content {
      maximum_concurrency = scaling_config.value
    }
  }
}
