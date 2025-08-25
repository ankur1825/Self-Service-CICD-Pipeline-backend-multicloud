locals {
  effective_subnet_ids = coalesce(var.subnet_ids, var.private_subnet_ids)
}
