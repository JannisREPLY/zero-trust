###############################################
# DATA SOURCES
###############################################
data "aws_caller_identity" "current" {}

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

###############################################
# VPC & NETWORK
###############################################
resource "aws_vpc" "secure_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = { Name = "insecure-vpc" }
}

resource "aws_flow_log" "secure_vpc_flow_log" {
  vpc_id               = aws_vpc.secure_vpc.id
  traffic_type         = "ALL"
  log_destination_type = "s3"
  log_destination      = aws_s3_bucket.alb_logs.arn
  iam_role_arn         = aws_iam_role.flow_logs_role.arn
}

data "aws_iam_policy_document" "flow_logs_assume_role_doc" {
  statement {
    effect = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "flow_logs_role" {
  name               = "vpc-flow-logs-to-s3"
  assume_role_policy = data.aws_iam_policy_document.flow_logs_assume_role_doc.json
}

# Policy to allow VPC Flow Logs to write to the ALB logs bucket
data "aws_iam_policy_document" "flow_logs_to_s3_doc" {
  statement {
    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:GetBucketLocation"
    ]
    resources = [
      # Bucket itself
      aws_s3_bucket.alb_logs.arn,
      # All objects in the bucket
      "${aws_s3_bucket.alb_logs.arn}/*"
    ]
  }
}

resource "aws_iam_role_policy" "flow_logs_to_s3" {
  name   = "vpc-flow-logs-to-s3-policy"
  role   = aws_iam_role.flow_logs_role.id
  policy = data.aws_iam_policy_document.flow_logs_to_s3_doc.json
}

resource "aws_subnet" "public_subnet_1" {
  vpc_id                  = aws_vpc.secure_vpc.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "eu-central-1a"
  tags = { Name = "public-subnet-1" }
}

resource "aws_subnet" "public_subnet_2" {
  vpc_id                  = aws_vpc.secure_vpc.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "eu-central-1b"
  tags = { Name = "public-subnet-2" }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.secure_vpc.id
  tags   = { Name = "insecure-igw" }
}

###############################################
# FIREWALL (Principle #1 - Distrust Everything)
###############################################
resource "aws_subnet" "firewall_subnet" {
  vpc_id            = aws_vpc.secure_vpc.id
  cidr_block        = "10.0.3.0/24"
  availability_zone = "eu-central-1a"
  tags = { Name = "firewall-subnet" }
}

resource "aws_networkfirewall_rule_group" "allow_all_stateless_rule_group" {
  capacity = 100
  name     = "allow-all-stateless-rule-group"
  type     = "STATELESS"

  encryption_configuration {
    key_id = aws_kms_key.network_kms.arn
    type = "CUSTOMER_KMS"
  }

  rule_group {
    rules_source {
      stateless_rules_and_custom_actions {
        stateless_rule {
          priority = 1
          rule_definition {
            actions = ["aws:forward_to_sfe"]
            match_attributes {
              source {
                address_definition = "0.0.0.0/0"
              }
              destination {
                address_definition = "0.0.0.0/0"
              }
            }
          }
        }
      }
    }
  }
}

resource "aws_networkfirewall_rule_group" "block_outside_DE" {
  capacity    = 100
  name        = "block-outside-DE"
  type        = "STATEFUL"

  encryption_configuration {
    key_id = aws_kms_key.network_kms.arn
    type = "CUSTOMER_KMS"
  }

  rule_group {
    rules_source {
      stateful_rule {
        action = "DROP"
        header {
          direction        = "FORWARD"
          protocol         = "HTTP"
          source_port      = "ANY"
          destination_port = "ANY"
          source           = "ANY"
          destination      = "ANY"
        }
        rule_option {
          keyword  = "sid"
          settings = ["1"]
        }
        rule_option {
          keyword  = "geoip"
          settings = ["src,!DE"]
        }
      }
    }
  }
}

resource "aws_networkfirewall_firewall_policy" "firewall_policy" {
  name = "allow-only-DE-policy"

  encryption_configuration {
    key_id = aws_kms_key.network_kms.arn
    type = "CUSTOMER_KMS"
  }

  firewall_policy {
    stateless_default_actions          = ["aws:forward_to_sfe"]
    stateless_fragment_default_actions = ["aws:forward_to_sfe"]

    stateless_rule_group_reference {
      resource_arn = aws_networkfirewall_rule_group.allow_all_stateless_rule_group.arn
      priority     = 1
    }

    stateful_engine_options {
      rule_order = "DEFAULT_ACTION_ORDER"
    }

    stateful_rule_group_reference {
      resource_arn = aws_networkfirewall_rule_group.block_outside_DE.arn
    }
  }
}

resource "aws_networkfirewall_firewall" "firewall" {
  name                = "Basic-Firewall"
  firewall_policy_arn = aws_networkfirewall_firewall_policy.firewall_policy.arn
  vpc_id              = aws_vpc.secure_vpc.id

  delete_protection = true

  encryption_configuration {
    key_id = aws_kms_key.network_kms.arn
    type = "CUSTOMER_KMS"
  }

  subnet_mapping {
    subnet_id = aws_subnet.firewall_subnet.id
  }
}

data "aws_iam_policy_document" "network_kms_policy" {
  statement {
    sid     = "Allow Administration of the KMS key to the account"
    effect  = "Allow"
    actions = [
      "kms:*" 
    ]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    resources = ["*"]
  }

  # Example: Additional usage permissions for a specific IAM role
  statement {
    sid     = "Allow use of the key"
    effect  = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey"
    ]
    principals {
      type        = "AWS"
      identifiers = [
        # For instance, allow an IAM role that might be used by Network Firewall
        "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/someNetworkFirewallRole"
      ]
    }
    resources = ["*"]
  }
}

resource "aws_kms_key" "network_kms" {
  description        = "KMS key for Network Firewall"
  enable_key_rotation = true

  # Attach the custom policy
  policy = data.aws_iam_policy_document.network_kms_policy.json
}

###############################################
# SECURITY GROUPS
###############################################
resource "aws_security_group" "secure_sg" {
  name        = "secure-sg"
  description = "Allow HTTPS inbound"
  vpc_id      = aws_vpc.secure_vpc.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["${var.allowed_ip}/32"]
    description = "Allow HTTPS inbound"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all egress"
  }
}

resource "aws_security_group" "rds_sg" {
  name        = "rds-security-group"
  description = "Allow DB traffic from secure_sg"
  vpc_id      = aws_vpc.secure_vpc.id

  ingress {
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.secure_sg.id]
    description = "Allow DB traffic from secure_sg"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow DB traffic from secure_sg"
  }
}

###############################################
# PRINCIPLE #2 - Minimizing Authorizations (IAM)
###############################################
resource "aws_iam_role" "ec2" {
  name               = "ec2"
  assume_role_policy = <<-EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": { "Service": "ec2.amazonaws.com" },
      "Effect": "Allow"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "ssm_managed_ec2" {
  role       = aws_iam_role.ec2.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_policy" "rds_connect_policy" {
  name   = "rds-connect-policy"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = "rds-db:connect",
        Resource = "arn:aws:rds-db:${var.aws_region}:${data.aws_caller_identity.current.account_id}:dbuser:${aws_db_instance.default.resource_id}/admin"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "rds_policy_attachment" {
  role       = aws_iam_role.ec2.name
  policy_arn = aws_iam_policy.rds_connect_policy.arn
}

resource "aws_iam_instance_profile" "ec2" {
  name = "ec2_profile"
  role = aws_iam_role.ec2.name
}

###############################################
# ENHANCED MONITORING FOR RDS (CKV_AWS_118)
###############################################
data "aws_iam_policy_document" "rds_enhanced_monitoring_assume" {
  statement {
    effect = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["monitoring.rds.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "rds_enhanced_monitoring" {
  name               = "rds-enhanced-monitoring"
  assume_role_policy = data.aws_iam_policy_document.rds_enhanced_monitoring_assume.json
}

resource "aws_iam_role_policy_attachment" "rds_enhanced_monitoring_attach" {
  role       = aws_iam_role.rds_enhanced_monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

data "aws_iam_policy_document" "rds_kms_policy" {
  statement {
    sid     = "Allow Administration of the KMS key to the account"
    effect  = "Allow"
    actions = ["kms:*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    resources = ["*"]
  }

  # Example usage permission for an RDS role or other principal
  statement {
    sid     = "Allow use of the key"
    effect  = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey"
    ]
    principals {
      type        = "AWS"
      identifiers = [
        "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/rdsEncryptionRole"
      ]
    }
    resources = ["*"]
  }
}

resource "aws_kms_key" "rds_kms" {
  description         = "KMS key for RDS encryption"
  enable_key_rotation = true
  policy              = data.aws_iam_policy_document.rds_kms_policy.json
}


###############################################
# RDS INSTANCE (Storage encryption + monitoring)
###############################################
resource "aws_db_subnet_group" "default" {
  name       = "main-db-subnet-group"
  subnet_ids = [aws_subnet.public_subnet_1.id, aws_subnet.public_subnet_2.id]
  tags       = { Name = "db-subnet-group" }
}

resource "aws_db_instance" "default" {
  allocated_storage                 = 5
  engine                            = "mysql"
  engine_version                    = "8.0"
  instance_class                    = "db.t3.micro"
  db_name                           = "mydb"
  username                          = "admin"
  password                          = "supersecret"
  skip_final_snapshot               = true
  db_subnet_group_name              = aws_db_subnet_group.default.name
  vpc_security_group_ids            = [aws_security_group.rds_sg.id]
  publicly_accessible               = false
  iam_database_authentication_enabled = true
  auto_minor_version_upgrade = true
  enabled_cloudwatch_logs_exports = ["general", "error", "slowquery"]
  multi_az             = true
  deletion_protection  = true

  # CKV_AWS_16: At-rest encryption
  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds_kms.arn
  performance_insights_kms_key_id = aws_kms_key.rds_kms.arn

  # CKV_AWS_118: Enhanced Monitoring
  monitoring_interval = 60
  monitoring_role_arn = aws_iam_role.rds_enhanced_monitoring.arn

  copy_tags_to_snapshot     = true

  tags = { Name = "my-rds-instance" }
}

###############################################
# RDS VPC ENDPOINT
###############################################
resource "aws_vpc_endpoint" "rds_endpoint" {
  vpc_id              = aws_vpc.secure_vpc.id
  service_name        = "com.amazonaws.${var.aws_region}.rds"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.public_subnet_1.id]
  security_group_ids  = [aws_security_group.rds_sg.id]
  private_dns_enabled = true

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "rds:Connect",
      "Resource": "arn:aws:rds:${var.aws_region}:${data.aws_caller_identity.current.account_id}:db/${aws_db_instance.default.id}"
    }
  ]
}
EOF
}

###############################################
# PRINCIPLE #3 - Continuous Monitoring (CloudTrail)
###############################################
resource "aws_s3_bucket" "cloudtrail_bucket" {
  bucket = "my-cloudtrail-logs-bucket"
  acl    = "private"
}

resource "aws_sns_topic" "cloudtrail_sns" {
  name = "cloudtrail-sns"
  kms_master_key_id = aws_kms_key.cloudtrail_kms.arn
}

data "aws_iam_policy_document" "cloudtrail_kms_policy" {
  statement {
    sid     = "Allow Administration of the KMS key to the account"
    effect  = "Allow"
    actions = ["kms:*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    resources = ["*"]
  }

  # Example usage permission for CloudTrail
  statement {
    sid     = "Allow CloudTrail to use the key"
    effect  = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey"
    ]
    principals {
      type        = "Service"
      identifiers = [
        "cloudtrail.amazonaws.com"
      ]
    }
    resources = ["*"]
  }
}

resource "aws_kms_key" "cloudtrail_kms" {
  description         = "KMS key for CloudTrail logs"
  enable_key_rotation = true
  policy              = data.aws_iam_policy_document.cloudtrail_kms_policy.json
}

resource "aws_cloudtrail" "main_trail" {
  name                          = "main-cloudtrail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_bucket.bucket
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_logging                = true

  # CKV_AWS_36: Enable log file validation
  enable_log_file_validation = true

  # CKV_AWS_35: Encrypt logs with KMS
  kms_key_id = aws_kms_key.cloudtrail_kms.arn

  # CKV_AWS_252: Define an SNS Topic
  sns_topic_name = aws_sns_topic.cloudtrail_sns.name
}

# Create an SQS queue to receive S3 event notifications
resource "aws_sqs_queue" "s3_event_queue" {
  name = "my-s3-event-queue"
}

# Example for the CloudTrail bucket
resource "aws_s3_bucket_notification" "cloudtrail_notifications" {
  bucket = aws_s3_bucket.cloudtrail_bucket.id

  queue {
    queue_arn = aws_sqs_queue.s3_event_queue.arn
    events    = ["s3:ObjectCreated:*"]
  }
}

# Example for the ALB logs bucket
resource "aws_s3_bucket_notification" "alb_logs_notifications" {
  bucket = aws_s3_bucket.alb_logs.id

  queue {
    queue_arn = aws_sqs_queue.s3_event_queue.arn
    events    = ["s3:ObjectCreated:*"]
  }
}

resource "aws_sqs_queue_policy" "s3_event_queue_policy" {
  queue_url = aws_sqs_queue.s3_event_queue.url
  policy    = data.aws_iam_policy_document.s3_event_queue_policy.json
}

data "aws_iam_policy_document" "s3_event_queue_policy" {
  statement {
    effect = "Allow"
    actions = [
      "SQS:SendMessage"
    ]
    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }
    resources = [aws_sqs_queue.s3_event_queue.arn]
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_s3_bucket.cloudtrail_bucket.arn, aws_s3_bucket.alb_logs.arn]
    }
  }
}

resource "aws_s3_bucket_versioning" "cloudtrail_versioning" {
  bucket = aws_s3_bucket.cloudtrail_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_versioning" "alb_logs_versioning" {
  bucket = aws_s3_bucket.alb_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

#
# 1) Create a new bucket for storing the access logs
#
resource "aws_s3_bucket" "access_logs_bucket" {
  bucket = "my-s3-access-logs-bucket"
  acl    = "log-delivery-write"
  # Optionally enable versioning and encryption here as well
}

#
# 2) Enable S3 server access logging for the CloudTrail bucket
#
resource "aws_s3_bucket_logging" "cloudtrail_access_logging" {
  bucket        = aws_s3_bucket.cloudtrail_bucket.id
  target_bucket = aws_s3_bucket.access_logs_bucket.id
  target_prefix = "cloudtrail/"
}

#
# 3) Enable S3 server access logging for the ALB logs bucket
#
resource "aws_s3_bucket_logging" "alb_logs_access_logging" {
  bucket        = aws_s3_bucket.alb_logs.id
  target_bucket = aws_s3_bucket.access_logs_bucket.id
  target_prefix = "alb/"
}


###############################################
# PRINCIPLE #4 - Micro-Segmentation
###############################################
resource "aws_subnet" "private_subnet_1" {
  vpc_id            = aws_vpc.secure_vpc.id
  cidr_block        = "10.0.10.0/24"
  availability_zone = "eu-central-1a"
  tags             = { Name = "private-subnet-1" }
}

###############################################
# ALB with Deletion Protection, Access Logging,
# and Dropping Invalid HTTP Headers
###############################################
resource "aws_s3_bucket" "alb_logs" {
  bucket = "my-alb-logs-bucket"
  acl    = "private"
}

resource "aws_lb" "public_alb" {
  name               = "public-alb"
  load_balancer_type = "application"
  subnets            = [
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

###############################################
# HTTPS Target Group with a Health Check
# (CKV_AWS_261: define health_check)
###############################################
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

  # REPLACE with a valid AWS Certificate Manager ARN
  #certificate_arn = "arn:aws:acm:REGION:ACCOUNT:certificate/VALID-CERT-ID"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.web_tg.arn
  }
}

###############################################
# The EC2 instance in a private subnet
###############################################
resource "aws_instance" "web_server" {
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.private_subnet_1.id
  vpc_security_group_ids = [aws_security_group.secure_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2.name

  ebs_optimized = true
  monitoring = true

  root_block_device {
    encrypted = true
  }

  metadata_options {
    http_endpoint = "enabled"
    http_tokens = "required"
  }

  tags = { Name = "web-server" }

  depends_on = [
    aws_lb_listener.alb_http_listener,
    aws_lb_listener.alb_https_listener
  ]
}

###############################################
# PRINCIPLE #5 - Zero Trust Access
###############################################
# Adjust resource name for the new provider naming convention
resource "aws_verifiedaccess_instance" "zero_trust" {
  description = "Zero Trust Access Instance"
}
