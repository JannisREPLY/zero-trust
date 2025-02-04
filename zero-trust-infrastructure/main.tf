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

resource "aws_vpc" "secure_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = { 
    Name = "secure-vpc" 
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

  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds_kms.arn
  performance_insights_kms_key_id = aws_kms_key.rds_kms.arn

  monitoring_interval = 60
  monitoring_role_arn = aws_iam_role.rds_enhanced_monitoring.arn

  copy_tags_to_snapshot = true

  tags = { 
    Name = "my-rds-instance" 
  }
}

resource "aws_instance" "web_app" {
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.private_subnet_1.id
  vpc_security_group_ids = [aws_security_group.secure_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2.name

  # The user_data script installs NGINX, starts it, and sets up a simple index.html.
  user_data = <<-EOF
    #!/bin/bash
    # Update the system
    yum update -y

    # Install NGINX
    amazon-linux-extras install -y nginx1
    systemctl start nginx
    systemctl enable nginx

    # Deploy a simple web page
    echo "<html><body><h1>Hello, Zero Trust!</h1><p>Your web app is running securely.</p></body></html>" > /usr/share/nginx/html/index.html
  EOF

  tags = {
    Name = "web-app"
  }
}
