# Output for remote state
output "global_network_id" {
  value = aws_networkmanager_global_network.global_network.id
}
output "sns_topic_arn" {
  value = aws_sns_topic.network_manager_events.arn
}
output "region_name" {
  value = data.aws_region.current.name
}