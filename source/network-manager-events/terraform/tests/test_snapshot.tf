# Intantiate the module
module "test_module" {
  source                            = "../"
  global_network_name               = "test"
  events_bus_name                   = "default"
  cloudwatch_logs_retention_in_days = 1
}
