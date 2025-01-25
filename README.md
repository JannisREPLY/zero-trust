Zero Trust AWS Infrastructure
=============================

This repository demonstrates a **Zero Trust** approach to building an AWS environment with Terraform. The code provisions a secure VPC setup with network firewall rules, restricted access to resources, continuous monitoring, micro-segmentation, and verified access. It also includes recommended security best practices such as encryption-at-rest for RDS, deletion protection, and KMS-based encryption for critical logs and network firewall resources.

Purpose
-------

-   **Minimal Attack Surface**\
    Everything starts from a position of no trust ("distrust everything"). Traffic is tightly controlled using **AWS Network Firewall**.
-   **Least Privilege**\
    User, service, and database permissions follow a least-privilege model. For example, the EC2 instance role only has permissions for `rds-db:connect`.
-   **Continuous Monitoring**\
    Logging and auditing are enabled via **Amazon CloudTrail**. Critical changes and events can be monitored in near real time.
-   **Micro-Segmentation**\
    The workload runs in private subnets behind an ALB in public subnets, limiting lateral movement in the network.
-   **Zero Trust Access**\
    Placeholder resources (e.g., **AWS Verified Access**) show how session posture checks can be enforced to maintain strict authentication and authorization.

Infrastructure Diagram
------------------------------------


`[ Diagram illustrating VPC, Firewall, ALB, Private Subnet, RDS, etc. ]`

Replace this placeholder with any architecture diagram you prefer.

GitHub Actions with Checkov
---------------------------

This repo can run **Checkov** scans via GitHub Actions to detect misconfigurations and security risks in the Terraform code. You can create a workflow like:

Whenever you push or open a pull request, Checkov will analyze the Terraform configuration and highlight potential security or compliance issues.

Usage
-----

1.  Clone the repo
2.  Configure AWS credentials
3.  Run `terraform init && terraform apply`
4.  (Optional) Add your own `.github/workflows/checkov.yml` to enable CI checks with GitHub Actions

This reference code is intended as an **example** for establishing a Zero Trust posture, showcasing core concepts rather than providing an exhaustive production-ready solution. Feel free to adapt the configuration to match your specific requirements.