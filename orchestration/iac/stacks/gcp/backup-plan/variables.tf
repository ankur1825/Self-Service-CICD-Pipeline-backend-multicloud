variable "region" {
  description = "Home region for the backup vault & plan"
  type        = string
}

variable "tags" {
  description = "Common tags to apply"
  type        = map(string)
  default     = {}
}

variable "vault_name" {
  description = "Backup vault name"
  type        = string
  default     = "maas-backup-vault"
}

variable "vault_kms_key_arn" {
  description = "KMS key ARN to encrypt the backup vault (optional)"
  type        = string
  default     = ""
}

variable "plan_name" {
  description = "Backup plan name"
  type        = string
  default     = "maas-backup-plan"
}

variable "schedule_cron" {
  description = "AWS Backup cron expression (e.g., cron(0 5 ? * * *))"
  type        = string
  default     = "cron(0 5 ? * * *)" # daily 05:00 UTC
}

variable "transition_to_cold_after_days" {
  description = "Move to cold storage after N days (0=never)"
  type        = number
  default     = 0
}

variable "delete_after_days" {
  description = "Delete after N days (required if transition_to_cold_after_days > 0)"
  type        = number
  default     = 35
}

variable "selection_tag_map" {
  description = "Tag selector for resources to protect (STRINGEQUALS). Example: { Backup = \"true\", App = \"demo\" }"
  type        = map(string)
  default     = { Backup = "true" }
}

# ---- Optional cross-Region copy ----
variable "enable_cross_region_copy" {
  description = "Enable cross-Region copy to a destination vault"
  type        = bool
  default     = false
}

variable "destination_region" {
  description = "Destination region for cross-Region copy"
  type        = string
  default     = ""
}

variable "destination_vault_name" {
  description = "Destination vault name in the destination region"
  type        = string
  default     = "maas-backup-vault-dr"
}

variable "destination_vault_kms_key_arn" {
  description = "KMS key ARN for the destination vault (optional)"
  type        = string
  default     = ""
}
