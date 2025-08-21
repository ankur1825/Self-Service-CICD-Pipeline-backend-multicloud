terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" { region = var.region }

# Reuse existing VPC or create a fresh one
data "aws_vpc" "existing" {
  count = var.existing_vpc_id != "" ? 1 : 0
  id    = var.existing_vpc_id
}

resource "aws_vpc" "lz" {
  count                = var.existing_vpc_id == "" ? 1 : 0
  cidr_block           = var.cidr_block
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags = merge(var.tags, { Name = "maas-lz" })
}

locals {
  vpc_id = var.existing_vpc_id != "" ? data.aws_vpc.existing[0].id : aws_vpc.lz[0].id
}

# Two private subnets across AZs
data "aws_availability_zones" "azs" { state = "available" }

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = local.vpc_id
  cidr_block        = cidrsubnet(var.cidr_block, 4, count.index + 1)
  availability_zone = data.aws_availability_zones.azs.names[count.index]
  map_public_ip_on_launch = false
  tags = merge(var.tags, { Name = "maas-private-${count.index}" })
}

# (Optional) NAT + private routes omitted for brevity

output "vpc_id" { value = local.vpc_id }
output "private_subnet_ids" { value = [for s in aws_subnet.private : s.id] }
