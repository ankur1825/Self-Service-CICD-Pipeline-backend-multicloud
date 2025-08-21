output "vault_name" {
  value = aws_backup_vault.src.name
}

output "plan_id" {
  value = aws_backup_plan.this.id
}

output "selection_id" {
  value = aws_backup_selection.this.id
}

output "destination_vault_arn" {
  value       = try(aws_backup_vault.dest[0].arn, null)
  description = "ARN of destination vault if cross-Region copy is enabled"
}
