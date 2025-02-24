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

resource "aws_default_security_group" "secure_vpc_default_sg" {
  vpc_id = aws_vpc.secure_vpc.id

  # No inbound rules => Deny all inbound
  ingress = []

  # No outbound rules => Deny all outbound
  egress = []
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
    
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
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

data "aws_iam_policy_document" "rds_kms_policy" {
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
    
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
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
