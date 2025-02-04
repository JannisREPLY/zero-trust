###############################################
# PRINCIPLE #4 - Micro-Segmentation
###############################################
resource "aws_subnet" "private_subnet_1" {
  vpc_id            = aws_vpc.secure_vpc.id
  cidr_block        = "10.0.10.0/24"
  availability_zone = "eu-central-1a"
  tags = { 
    Name = "private-subnet-1" 
  }
}

resource "aws_subnet" "public_subnet_1" {
  vpc_id            = aws_vpc.secure_vpc.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "eu-central-1a"
  tags = { 
    Name = "public-subnet-1" 
  }
}

resource "aws_subnet" "public_subnet_2" {
  vpc_id            = aws_vpc.secure_vpc.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "eu-central-1b"
  tags = { 
    Name = "public-subnet-2" 
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.secure_vpc.id
  tags   = { 
    Name = "insecure-igw" 
  }
}

resource "aws_s3_bucket" "alb_logs" {
  #checkov:skip=CKV_AWS_144: Overkill - Replication
  bucket = "my-alb-logs-bucket"
  acl    = "private"
}

resource "aws_lb" "public_alb" {
  name               = "public-alb"
  load_balancer_type = "application"
  subnets = [
    aws_subnet.public_subnet_1.id,
    aws_subnet.public_subnet_2.id
  ]
  security_groups = [aws_security_group.secure_sg.id]

  # Enable ALB deletion protection
  enable_deletion_protection = true

  # Drop invalid HTTP headers
  drop_invalid_header_fields = true

  # Access logging
  access_logs {
    bucket  = aws_s3_bucket.alb_logs.bucket
    enabled = true
    prefix  = "my-alb-logs"
  }

  tags = {
    Name = "public-alb"
  }
}

resource "aws_wafv2_web_acl" "example_waf" {
  name        = "example-wafv2-acl"
  scope       = "REGIONAL"
  description = "Basic WAF for public ALB with Log4j protection"

  default_action {
    allow {}
  }

  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 2

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      sampled_requests_enabled   = true
      metric_name                = "awsBadInputsRules"
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    sampled_requests_enabled   = true
    metric_name                = "exampleWebACL"
  }
}

resource "aws_wafv2_web_acl_association" "waf_alb_association" {
  resource_arn = aws_lb.public_alb.arn
  web_acl_arn  = aws_wafv2_web_acl.example_waf.arn
}

resource "aws_wafv2_web_acl_logging_configuration" "waf_logging" {
  log_destination_configs = [aws_cloudwatch_log_group.cloudtrail.arn]
  resource_arn           = aws_wafv2_web_acl.example_waf.arn
}

resource "aws_lb_target_group" "web_tg" {
  name        = "web-tg"
  port        = 443
  protocol    = "HTTPS"
  vpc_id      = aws_vpc.secure_vpc.id
  target_type = "instance"

  health_check {
    protocol = "HTTPS"
    path     = "/healthcheck"
  }
}

resource "aws_lb_listener" "alb_http_listener" {
  load_balancer_arn = aws_lb.public_alb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}


resource "aws_lb_listener" "alb_https_listener" {
  load_balancer_arn = aws_lb.public_alb.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.web_tg.arn
  }
}

resource "aws_instance" "web_server" {
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.private_subnet_1.id
  vpc_security_group_ids = [aws_security_group.secure_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2.name

  ebs_optimized = true
  monitoring    = true

  root_block_device {
    encrypted = true
  }

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  tags = { 
    Name = "web-server" 
  }

  depends_on = [
    aws_lb_listener.alb_http_listener,
    aws_lb_listener.alb_https_listener
  ]
}
