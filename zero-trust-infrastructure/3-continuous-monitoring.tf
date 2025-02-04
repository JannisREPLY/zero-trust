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
    sid     = "EnableRootManagement"
    effect  = "Allow"
    actions = [
      "kms:*"
    ]
    principals {
      type        = "AWS"
      identifiers = [
        "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
      ]
    }
    resources = ["*"]
  }
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

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_enc" {
  bucket = aws_s3_bucket.cloudtrail_bucket.bucket
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.cloudtrail_kms.arn
    }
  }
}

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
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
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

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
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

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
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