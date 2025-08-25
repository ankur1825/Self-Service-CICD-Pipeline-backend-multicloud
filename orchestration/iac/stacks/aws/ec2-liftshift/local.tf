locals {
  effective_subnet_ids = coalesce(var.subnet_ids, var.private_subnet_ids)
  map_types  = length(var.instance_type_map) > 0 ? distinct(values(var.instance_type_map)) : []
  use_mip    = length(local.map_types) > 1
  primary_it = length(local.map_types) > 0 ? local.map_types[0] : var.instance_type
}
