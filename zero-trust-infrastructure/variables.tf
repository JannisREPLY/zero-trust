variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "eu-central-1"
}

variable "aws_region_replication" {
  description = "AWS region to deploy replication resources"
  type = string
  default = "eu-west-1"
}

variable "allowed_ip" {
  description = "IP that is allowed to access the web application"
  type        = string
}