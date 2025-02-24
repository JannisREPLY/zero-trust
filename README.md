# AWS Zero Trust Infrastructure Example

This repository contains a comprehensive Terraform configuration that demonstrates an AWS infrastructure built in accordance with the five principles of Zero Trust Security. The configuration covers aspects such as strict firewall policies, least privilege IAM roles, continuous monitoring, network micro-segmentation, and zero trust access mechanisms.

> **Note:** This project is intended as an example and should be tailored to meet your organization's specific security requirements.

## Overview

The project is organized into multiple Terraform files, each focusing on one or more of the Zero Trust principles:

1.  **Distrust Everything (Principle #1)**

    -   **File:** [1-distruft-of-everything.tf](zero-trust-infrastructure/1-distrust-of-everything.tf)
    -   **Highlights:**
        -   Dedicated firewall subnet and restrictive default security groups (no inbound/outbound traffic).
        -   AWS Network Firewall configuration with custom stateless and stateful rule groups.
        -   Logging configuration to capture both flow and alert logs via Amazon S3.
2.  **Minimizing Authorizations (Principle #2)**

    -   **File:** [2-least-privilege.tf](zero-trust-infrastructure/2-least-privilege.tf)
    -   **Highlights:**
        -   Creation of IAM roles and policies for EC2 and RDS with the minimum required permissions.
        -   Enforcement of IAM DB authentication for RDS.
        -   Use of instance profiles and enhanced monitoring roles with least privilege.
3.  **Continuous Monitoring (Principle #3)**

    -   **File:** [3-continous-monitoring.tf](zero-trust-infrastructure/3-continuous-monitoring.tf)
    -   **Highlights:**
        -   Deployment of AWS CloudTrail for comprehensive logging.
        -   Configurations for S3 bucket logging, versioning, and lifecycle management for log retention.
        -   Integration with Amazon SNS and CloudWatch Logs for real-time monitoring and alerting.
        -   Setup of VPC Flow Logs for network traffic analysis.
4.  **Micro-Segmentation (Principle #4)**

    -   **File:** [4-micro-segmentation.tf](zero-trust-infrastructure/4-micro-segmentation.tf)
    -   **Highlights:**
        -   Definition of multiple subnets (public and private) within a secure VPC.
        -   Configuration of an Application Load Balancer (ALB) with WAF protection.
        -   Isolation of resources via dedicated subnets and controlled internet gateway access.
5.  **Zero Trust Access (Principle #5)**

    -   **File:** [5-zero-trust-access.tf](zero-trust-infrastructure/5-zero-trust-access.tf)
    -   **Highlights:**
        -   An example (currently commented out) of OIDC-based authentication on the ALB to enforce zero trust access.
        -   Demonstrates how to secure access to application endpoints using an external identity provider.

Additionally, shared resources and dependencies (like the VPC, RDS instance, EC2 instances, etc.) are defined in [main.tf](zero-trust-infrastructure/main.tf).

## Prerequisites

-   **Terraform:** Download and install Terraform (v0.12+ recommended)
-   **AWS Account:** Ensure you have an AWS account with sufficient permissions to create the resources.
-   **AWS CLI:** Configure the AWS CLI with your credentials (or use an appropriate Terraform provider configuration).
-   **Basic Knowledge:** Familiarity with AWS services (VPC, IAM, CloudTrail, etc.) and Terraform.

## Getting Started

1.  **Clone the Repository:**


    `git clone <repository_url>
    cd <repository_directory>`

2.  **Initialize Terraform:**

    `terraform init`

3.  **Review the Execution Plan:**

    `terraform plan`

4.  **Apply the Configuration:**

    `terraform apply`

    Confirm the prompt to proceed with resource creation.

5.  **Verify Deployment:**

    -   Check the AWS Management Console to verify that the resources (VPC, subnets, firewall, RDS, etc.) have been created as expected.
    -   Ensure CloudTrail and VPC Flow Logs are capturing activity for continuous monitoring.

## Configuration

-   **Variables:** Adjust any variables (e.g., `var.aws_region`, `var.allowed_ip`) in a `terraform.tfvars` file or via the command line to match your environment.
-   **Certificates:** If you plan to enable HTTPS on the ALB listener, supply a valid certificate ARN in the commented section within [5-zero-trust-access.tf](zero-trust-infrastructure/5-zero-trust-access.tf).
-   **Security Policies:** Review and customize IAM policies, security group rules, and other security-related settings to meet your compliance and security guidelines.

## Cleanup

To remove all resources created by this Terraform configuration, run:

`terraform destroy`
