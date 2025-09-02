variable "wave_id" { 
    type = string 
}
variable "targets" { 
    type = list(string) 
}
variable "region" { 
    type = string 
}
variable "vpc_id" { 
    type = string 
}
variable "subnet_ids" {
  type     = list(string)
  default  = null
  nullable = true
}
variable "private_subnet_ids" { 
    type = list(string) 
    default = null 
}
variable "security_group_ids" { 
    type = list(string) 
}
variable "instance_type_map" { 
    type = map(string) 
    default = {}
}
variable "tg_health_check_path" { 
    type = string 
    default = "/healthz" 
}
variable "blue_green" { 
    type = bool    
    default = true 
}
variable "attach_backup" { 
    type = bool    
    default = true 
}
variable "kms_key_alias" { 
    type = string  
    default = "alias/tenant-data" 
}
variable "copy_to_region" { 
    type = string  
    default = null 
}
variable "tags" { 
    type = map(string) 
    default = {} 
}
variable "instance_type" {
  type    = string
  default = "m6i.large"
}
variable "image_id" {
  description = "AMI for Launch Template; if null, auto-select latest Amazon Linux 2023"
  type        = string
  default     = null
}
