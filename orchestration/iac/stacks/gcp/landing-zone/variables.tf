variable "region" { 
    type = string 
}
variable "existing_vpc_id" { 
    type = string 
    default = "" 
}
variable "cidr_block" { 
    type = string 
    default = "10.0.0.0/16" 
}
variable "enable_nat" { 
    type = bool 
    default = true 
}
variable "tags" { 
    type = map(string) 
    default = {} 
}