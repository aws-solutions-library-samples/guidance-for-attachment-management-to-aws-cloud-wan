variable "global_network_name" {
  description = "Name for the Network Manager Global Network to be created"
  type        = string
}

variable "events_bus_name" {
  description = "Name for the Eventbridge Bus to be used for rule configuration"
  type        = string
  default     = "default"
}
