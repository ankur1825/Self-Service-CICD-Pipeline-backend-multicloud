terraform {
  backend "s3" {}
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

# Optional provider for destination region (for cross-region copy)
provider "aws" {
  alias  = "dest"
  region = var.destination_region != "" ? var.destination_region : var.region
}

# --- Vault(s): create-or-use ---
resource "aws_backup_vault" "src" {
  count = var.create_vault ? 1 : 0
  name  = var.vault_name
  # kms_key_arn = var.vault_kms_key_arn != "" ? var.vault_kms_key_arn : null
  tags  = merge(var.tags, { Name = var.vault_name })
}

data "aws_backup_vault" "src" {
  count = var.create_vault ? 0 : 1
  name  = var.vault_name
}

# Destination vault (only when cross-region copy enabled)
resource "aws_backup_vault" "dest" {
  count       = var.enable_cross_region_copy ? 1 : 0
  provider    = aws.dest
  name        = var.destination_vault_name
  kms_key_arn = var.destination_vault_kms_key_arn != "" ? var.destination_vault_kms_key_arn : null
  tags        = merge(var.tags, { Name = var.destination_vault_name })
}

# --- IAM role: create-or-use ---
data "aws_iam_policy_document" "assume_backup" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["backup.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "backup" {
  count              = var.create_iam_role ? 1 : 0
  name               = var.iam_role_name
  assume_role_policy = data.aws_iam_policy_document.assume_backup.json
  tags               = var.tags
}

data "aws_iam_role" "backup" {
  count = var.create_iam_role ? 0 : 1
  name  = var.iam_role_name
}

# Attach AWS managed policies only if we created the role
resource "aws_iam_role_policy_attachment" "backup" {
  count      = var.create_iam_role ? 1 : 0
  role       = aws_iam_role.backup[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
}

resource "aws_iam_role_policy_attachment" "restore" {
  count      = var.create_iam_role ? 1 : 0
  role       = aws_iam_role.backup[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForRestores"
}

# --- Fan-in locals (safe in both create and reuse modes) ---
locals {
  vault_name       = coalescelist(aws_backup_vault.src[*].name, data.aws_backup_vault.src[*].name)[0]
  vault_arn        = coalescelist(aws_backup_vault.src[*].arn,  data.aws_backup_vault.src[*].arn)[0]
  backup_role_arn  = coalescelist(aws_iam_role.backup[*].arn,   data.aws_iam_role.backup[*].arn)[0]
}

# --- Plan (use locals, never reference counted resources directly) ---
resource "aws_backup_plan" "this" {
  name = var.plan_name
  tags = var.tags

  rule {
    rule_name                    = "${var.plan_name}-daily"
    schedule                     = var.schedule_cron
    target_vault_name            = local.vault_name
    start_window                 = 60
    completion_window            = 180

    lifecycle {
      cold_storage_after = var.transition_to_cold_after_days > 0 ? var.transition_to_cold_after_days : null
      delete_after       = var.delete_after_days
    }

    dynamic "copy_action" {
      for_each = var.enable_cross_region_copy ? [1] : []
      content {
        destination_vault_arn = aws_backup_vault.dest[0].arn
      }
    }
  }
}

# Use role in selection
resource "aws_backup_selection" "this" {
  plan_id      = aws_backup_plan.this.id
  name         = "${var.plan_name}-selection"
  iam_role_arn = local.backup_role_arn

  dynamic "selection_tag" {
    for_each = var.selection_tag_map
    content {
      type  = "STRINGEQUALS"
      key   = selection_tag.key
      value = selection_tag.value
    }
  }
}
