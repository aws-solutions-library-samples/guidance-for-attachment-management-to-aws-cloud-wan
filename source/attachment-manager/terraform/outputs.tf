# Output for remote state
output "lambda_routing_config_local_package" {
  value = module.lambda_routing_config_on_demand.local_filename
}

output "lambda_routing_config_role_arn" {
  value = module.lambda_routing_config_on_demand.lambda_role_arn
}