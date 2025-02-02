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
  tags = { 
    Name = "secure-vpc" 
  }
}

resource "aws_default_security_group" "secure_vpc_default_sg" {
  vpc_id = aws_vpc.secure_vpc.id

  # No inbound rules => Deny all inbound
  ingress = []

  # No outbound rules => Deny all outbound
  egress = []
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
      aws_s3_bucket.alb_logs.arn,
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

###############################################
# FIREWALL (Principle #1 - Distrust Everything)
###############################################
resource "aws_subnet" "firewall_subnet" {
  vpc_id            = aws_vpc.secure_vpc.id
  cidr_block        = "10.0.3.0/24"
  availability_zone = "eu-central-1a"
  tags = { 
    Name = "firewall-subnet" 
  }
}

resource "aws_networkfirewall_logging_configuration" "firewall_logs" {
  firewall_arn = aws_networkfirewall_firewall.firewall.arn

  logging_configuration {
    log_destination_config {
      # Log Type = FLOW or ALERT (you can define one or both)
      log_type             = "FLOW"
      log_destination_type = "S3"

      # “log_destination” is a map of required properties for that type
      log_destination = {
        bucketName = aws_s3_bucket.access_logs_bucket.bucket
        # Optional prefix: "firewall-logs/"
      }
    }

    # Example of also enabling ALERT logs to the same or different destination
    log_destination_config {
      log_type             = "ALERT"
      log_destination_type = "S3"
      log_destination = {
        bucketName = aws_s3_bucket.access_logs_bucket.bucket
      }
    }
  }
}

resource "aws_networkfirewall_rule_group" "allow_all_stateless_rule_group" {
  capacity = 100
  name     = "allow-all-stateless-rule-group"
  type     = "STATELESS"

  encryption_configuration {
    key_id = aws_kms_key.network_kms.arn
    type   = "CUSTOMER_KMS"
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
  capacity = 100
  name     = "block-outside-DE"
  type     = "STATEFUL"

  encryption_configuration {
    key_id = aws_kms_key.network_kms.arn
    type   = "CUSTOMER_KMS"
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
    type   = "CUSTOMER_KMS"
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
  delete_protection    = true

  encryption_configuration {
    key_id = aws_kms_key.network_kms.arn
    type   = "CUSTOMER_KMS"
  }

  subnet_mapping {
    subnet_id = aws_subnet.firewall_subnet.id
  }
}

data "aws_iam_policy_document" "network_kms_policy" {
  statement {
    sid     = "AllowNetworkFirewallUseKey"
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
        "network-firewall.amazonaws.com"
      ]
    }

    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = [
        "network-firewall.${var.aws_region}.amazonaws.com"
      ]
    }
  }
}

resource "aws_kms_key" "network_kms" {
  description         = "KMS key for Network Firewall"
  enable_key_rotation = true

  # Attach the custom policy above
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
    description     = "Allow DB traffic from secure_sg"
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

# Policy for IAM DB Authentication
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


###############################################
# KMS KEY FOR RDS
###############################################
data "aws_iam_policy_document" "rds_kms_policy" {
  statement {
    sid     = "AllowRDSUseKey"
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
        "rds.amazonaws.com"
      ]
    }

    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = [
        "rds.${var.aws_region}.amazonaws.com"
      ]
    }
  }
}

resource "aws_kms_key" "rds_kms" {
  description         = "KMS key for RDS encryption"
  enable_key_rotation = true
  policy              = data.aws_iam_policy_document.rds_kms_policy.json
}

resource "aws_db_subnet_group" "default" {
  name       = "main-db-subnet-group"
  subnet_ids = [aws_subnet.public_subnet_1.id, aws_subnet.public_subnet_2.id]
  tags       = { 
    Name = "db-subnet-group" 
  }
}

resource "aws_db_instance" "default" {
  allocated_storage                  = 5
  engine                             = "mysql"
  engine_version                     = "8.0"
  instance_class                     = "db.t3.micro"
  db_name                            = "mydb"
  username                           = "admin"
  password                           = "supersecret"
  skip_final_snapshot                = true
  db_subnet_group_name               = aws_db_subnet_group.default.name
  vpc_security_group_ids             = [aws_security_group.rds_sg.id]
  publicly_accessible                = false
  iam_database_authentication_enabled = true
  auto_minor_version_upgrade         = true
  enabled_cloudwatch_logs_exports    = ["general", "error", "slowquery"]
  multi_az                           = true
  deletion_protection                = true

  # CKV_AWS_16: At-rest encryption
  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds_kms.arn
  performance_insights_kms_key_id = aws_kms_key.rds_kms.arn

  # CKV_AWS_118: Enhanced Monitoring
  monitoring_interval = 60
  monitoring_role_arn = aws_iam_role.rds_enhanced_monitoring.arn

  copy_tags_to_snapshot = true

  tags = { 
    Name = "my-rds-instance" 
  }
}

resource "aws_vpc_endpoint" "rds_endpoint" {
  vpc_id            = aws_vpc.secure_vpc.id
  service_name      = "com.amazonaws.${var.aws_region}.rds"
  vpc_endpoint_type = "Interface"
  subnet_ids        = [aws_subnet.public_subnet_1.id]
  security_group_ids = [
    aws_security_group.rds_sg.id
  ]
  private_dns_enabled = true

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "rds-db:connect",
      "Resource": "arn:aws:rds:${var.aws_region}:${data.aws_caller_identity.current.account_id}:db:${aws_db_instance.default.id}"
    }
  ]
}
EOF
}

###############################################
# PRINCIPLE #3 - Continuous Monitoring (CloudTrail)
###############################################
resource "aws_s3_bucket" "cloudtrail_bucket" {
  #checkov:skip=CKV_AWS_144: Overkill - Replication
  bucket = "my-cloudtrail-logs-bucket"
  acl    = "private"
}

resource "aws_sns_topic" "cloudtrail_sns" {
  name             = "cloudtrail-sns"
  kms_master_key_id = aws_kms_key.cloudtrail_kms.arn
}

data "aws_iam_policy_document" "cloudtrail_kms_policy" {
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
        "cloudtrail.amazonaws.com",
        "logs.amazonaws.com"
      ]
    }

    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = [
        "cloudtrail.${var.aws_region}.amazonaws.com"
      ]
    }
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = [
        "logs.${var.aws_region}.amazonaws.com"
      ]
    }
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

  cloud_watch_logs_group_arn = aws_cloudwatch_log_group.cloudtrail.arn
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_cw_role.arn

  # CKV_AWS_36: Enable log file validation
  enable_log_file_validation = true

  # CKV_AWS_35: Encrypt logs with KMS
  kms_key_id = aws_kms_key.cloudtrail_kms.arn

  # CKV_AWS_252: Define an SNS Topic
  sns_topic_name = aws_sns_topic.cloudtrail_sns.name
}

# Create an SQS queue to receive S3 event notifications
resource "aws_sqs_queue" "s3_event_queue" {
  name                             = "my-s3-event-queue"
  kms_master_key_id                = aws_kms_key.cloudtrail_kms.arn
  kms_data_key_reuse_period_seconds = 300
}

# Example for CloudTrail bucket
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
      values   = [
        aws_s3_bucket.cloudtrail_bucket.arn,
        aws_s3_bucket.alb_logs.arn
      ]
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

resource "aws_s3_bucket" "access_logs_bucket" {
  #checkov:skip=CKV_AWS_144: Overkill - Replication
  bucket = "my-s3-access-logs-bucket"
  acl    = "log-delivery-write"
}

resource "aws_s3_bucket_logging" "cloudtrail_access_logging" {
  bucket        = aws_s3_bucket.cloudtrail_bucket.id
  target_bucket = aws_s3_bucket.access_logs_bucket.id
  target_prefix = "cloudtrail/"
}

resource "aws_s3_bucket_versioning" "access_logs_versioning" {
  bucket = aws_s3_bucket.access_logs_bucket.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_logging" "alb_logs_access_logging" {
  bucket        = aws_s3_bucket.alb_logs.id
  target_bucket = aws_s3_bucket.access_logs_bucket.id
  target_prefix = "alb/"
}

resource "aws_s3_bucket_notification" "access_logs_bucket_notifications" {
  bucket = aws_s3_bucket.access_logs_bucket.id

  # Example: Send event notifications to an existing SQS queue
  queue {
    queue_arn = aws_sqs_queue.s3_event_queue.arn
    events    = ["s3:ObjectCreated:*"]
    
    # Optionally define filters for prefix, suffix, etc. if needed
    # filter_prefix = "some/path/"
    # filter_suffix = ".log"
  }
}

# For the CloudTrail logs bucket
resource "aws_s3_bucket_public_access_block" "cloudtrail_bucket_block" {
  bucket = aws_s3_bucket.cloudtrail_bucket.bucket

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# For the access logs bucket
resource "aws_s3_bucket_public_access_block" "access_logs_bucket_block" {
  bucket = aws_s3_bucket.access_logs_bucket.bucket

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# For the ALB logs bucket
resource "aws_s3_bucket_public_access_block" "alb_logs_bucket_block" {
  bucket = aws_s3_bucket.alb_logs.bucket

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

##############################################################################
# 1) CloudTrail bucket encrypted with a CUSTOM KMS key you already created.
##############################################################################
resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_enc" {
  bucket = aws_s3_bucket.cloudtrail_bucket.bucket
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.cloudtrail_kms.arn
    }
  }
}

##############################################################################
# 2) Access logs bucket encrypted with the AWS-managed KMS key for S3.
#    (Or create your own custom KMS key.)
##############################################################################
resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs_enc" {
  bucket = aws_s3_bucket.access_logs_bucket.bucket

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      # For simplicity, use the AWS-managed key:
      kms_master_key_id = "alias/aws/s3"
    }
  }
}

##############################################################################
# 3) ALB logs bucket encrypted with the AWS-managed KMS key for S3.
##############################################################################
resource "aws_s3_bucket_server_side_encryption_configuration" "alb_logs_enc" {
  bucket = aws_s3_bucket.alb_logs.bucket

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = "alias/aws/s3"
    }
  }
}

resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/logs"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.cloudtrail_kms.arn
}

data "aws_iam_policy_document" "cloudtrail_assume_role" {
  statement {
    effect = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "cloudtrail_cw_role" {
  name               = "cloudtrail-cloudwatch-role"
  assume_role_policy = data.aws_iam_policy_document.cloudtrail_assume_role.json
}

data "aws_iam_policy_document" "cloudtrail_cw_logs_policy_doc" {
  statement {
    effect = "Allow"
    actions = [
      "logs:PutLogEvents",
      "logs:CreateLogStream"
    ]
    # If you want CloudTrail to create the log group automatically,
    # you could also include "logs:CreateLogGroup" here. 
    resources = [
      "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
    ]
  }
}

resource "aws_iam_policy" "cloudtrail_cw_logs_policy" {
  name   = "cloudtrail-cloudwatch-logs"
  policy = data.aws_iam_policy_document.cloudtrail_cw_logs_policy_doc.json
}

resource "aws_iam_role_policy_attachment" "cloudtrail_cw_logs_attach" {
  role       = aws_iam_role.cloudtrail_cw_role.name
  policy_arn = aws_iam_policy.cloudtrail_cw_logs_policy.arn
}

resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail_lifecycle" {
  bucket = aws_s3_bucket.cloudtrail_bucket.id

  rule {
    id     = "transition-cloudtrail-logs"
    status = "Enabled"

    transition {
      days          = 30  # Move to Standard-IA after 30 days
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 90  # Move to Glacier Deep Archive after 90 days
      storage_class = "DEEP_ARCHIVE"
    }

    expiration {
      days = 365  # Delete logs after 1 year
    }
  }

  rule {
    id     = "abort-multipart-uploads"
    status = "Enabled"

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "alb_logs_lifecycle" {
  bucket = aws_s3_bucket.alb_logs.id

  rule {
    id     = "transition-alb-logs"
    status = "Enabled"

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = 365
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "access_logs_lifecycle" {
  bucket = aws_s3_bucket.access_logs_bucket.id

  rule {
    id     = "transition-access-logs"
    status = "Enabled"

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = 365
    }
  }
}

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

  # ✅ Add AWS Log4j Protection Rule
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

###############################################
# PRINCIPLE #5 - Zero Trust Access
###############################################
resource "aws_verifiedaccess_instance" "zero_trust" {
  description = "Zero Trust Access Instance"
}
