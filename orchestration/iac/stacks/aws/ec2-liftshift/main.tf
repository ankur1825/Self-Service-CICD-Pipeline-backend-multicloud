terraform {
  backend "s3" {}
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}
provider "aws" { region = var.region }

resource "aws_lb" "app" {
  name               = "maas-alb"
  load_balancer_type = "application"
  security_groups    = var.security_group_ids
  subnets            = local.effective_subnet_ids   # <= was var.subnet_ids
  tags               = var.tags
}

resource "aws_lb_target_group" "prod" {
  name     = "maas-tg-prod"
  port     = 80
  protocol = "HTTP"
  vpc_id   = var.vpc_id
  health_check {
    path                = var.tg_health_check_path
    matcher             = "200-299"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    interval            = 15
  }
  tags = var.tags
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.app.arn
  port              = "80"
  protocol          = "HTTP"
  default_action { 
    type = "forward" 
    target_group_arn = aws_lb_target_group.prod.arn 
    }
}

data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]

  filter { 
    name = "name"         
    values = ["al2023-ami-*-x86_64"] 
    } # adjust to arm64 if needed
  filter { 
    name = "state"        
    values = ["available"] 
    }
}

locals {
  lt_image_id = var.image_id != null && var.image_id != "" ? var.image_id : data.aws_ami.al2023.id
}

# A generic Launch Template. AMI IDs will be *overridden* by MGN at cutover.
resource "aws_launch_template" "lt" {
  name_prefix   = "maas-lt-"
  image_id      = local.lt_image_id      #"ami-00000000000000000"   placeholder; MGN overrides on launch
  instance_type = local.primary_it
  vpc_security_group_ids = var.security_group_ids
  tag_specifications { 
    resource_type = "instance" 
    tags = var.tags 
    }
  metadata_options { http_tokens = "required" }
}

resource "aws_autoscaling_group" "asg" {
  name                = "maas-asg"
  desired_capacity    = length(var.instance_type_map)
  min_size            = 0
  max_size            = length(var.instance_type_map)
  vpc_zone_identifier = local.effective_subnet_ids

  # If there is only ONE instance type, attach the LT directly
  dynamic "launch_template" {
    for_each = local.use_mip ? [] : [1]
    content {
      id      = aws_launch_template.lt.id
      version = "$Latest"
    }
  }

  # If there are MULTIPLE instance types, use MixedInstancesPolicy with overrides
  dynamic "mixed_instances_policy" {
    for_each = local.use_mip ? [1] : []
    content {
      launch_template {
        launch_template_specification {
          launch_template_id = aws_launch_template.lt.id
          version            = "$Latest"
        }
        dynamic "override" {
          for_each = toset(local.map_types)
          content {
            instance_type = override.value
          }
        }
      }
      # (Optional) add on_demand_base_capacity / on_demand_percentage_above_base_capacity
      # if you want Spot mixing later.
    }
  }

  target_group_arns = [aws_lb_target_group.prod.arn]

  tag {
    key                 = "Name"
    value               = "maas-ec2"
    propagate_at_launch = true
  }
}

output "alb_dns_name" { 
    value = aws_lb.app.dns_name 
}
output "tg_arn"       { 
    value = aws_lb_target_group.prod.arn 
}
output "lt_id"        { 
    value = aws_launch_template.lt.id 
}
