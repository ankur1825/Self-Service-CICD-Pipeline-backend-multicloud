variable "region" { 
    type = string 
}
variable "vpc_id" { 
    type = string 
}
variable "subnet_ids" { 
    type = list(string) 
}
variable "security_group_ids" { 
    type = list(string) 
}
variable "instance_type_map" { 
    type = map(string) 
}
variable "tg_health_check_path" { 
    type = string 
    default = "/healthz" 
}
variable "tags" { 
    type = map(string) 
    default = {} 
}
