terraform {
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

# optional provider for destination region
provider "aws" {
  alias  = "dest"
  region = var.destination_region != "" ? var.destination_region : var.region
}

# --- Vault(s) ---
resource "aws_backup_vault" "src" {
  name        = var.vault_name
  kms_key_arn = var.vault_kms_key_arn != "" ? var.vault_kms_key_arn : null
  tags        = merge(var.tags, { Name = var.vault_name })
}

resource "aws_backup_vault" "dest" {
  count       = var.enable_cross_region_copy ? 1 : 0
  provider    = aws.dest
  name        = var.destination_vault_name
  kms_key_arn = var.destination_vault_kms_key_arn != "" ? var.destination_vault_kms_key_arn : null
  tags        = merge(var.tags, { Name = var.destination_vault_name })
}

# --- Plan ---
resource "aws_backup_plan" "this" {
  name = var.plan_name
  rule {
    rule_name         = "${var.plan_name}-daily"
    target_vault_name = aws_backup_vault.src.name
    schedule          = var.schedule_cron

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

  tags = var.tags
}

# --- IAM role used by selection ---
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
  name               = "maas-backup-role"
  assume_role_policy = data.aws_iam_policy_document.assume_backup.json
  tags               = var.tags
}

# Attach AWS managed policies for backup/restore
resource "aws_iam_role_policy_attachment" "backup" {
  role       = aws_iam_role.backup.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
}

resource "aws_iam_role_policy_attachment" "restore" {
  role       = aws_iam_role.backup.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForRestores"
}

# --- Selection by tags ---
resource "aws_backup_selection" "this" {
  iam_role_arn = aws_iam_role.backup.arn
  name         = "${var.plan_name}-selection"
  plan_id      = aws_backup_plan.this.id

  dynamic "selection_tag" {
    for_each = var.selection_tag_map
    content {
      type  = "STRINGEQUALS"
      key   = selection_tag.key
      value = selection_tag.value
    }
  }
}
