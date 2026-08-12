# -------------------------------------------------------------------------
# Intentionally Vulnerable AWS Infrastructure for DriftWatch Testing
# 
# Acknowledgment: 
# The methodology for generating these specific AWS misconfigurations 
# is inspired by the open-source 'sadcloud' project by NCC Group.
# Repository: https://github.com/nccgroup/sadcloud
# -------------------------------------------------------------------------

provider "aws" {
  region = "us-east-1"
}

# 1. Custom VPC and Subnet (100% Free)
resource "aws_vpc" "sadcloud_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name = "DriftWatch-Sadcloud-VPC"
  }
}

resource "aws_subnet" "sadcloud_subnet" {
  vpc_id                  = aws_vpc.sadcloud_vpc.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
  tags = {
    Name = "DriftWatch-Sadcloud-Subnet"
  }
}

# 2. Vulnerable Security Group (Ports 22 & 3389 open to the Internet)
resource "aws_security_group" "sadcloud_vulnerable_sg" {
  name        = "sadcloud-vulnerable-sg"
  description = "Intentionally vulnerable SG with open SSH and RDP"
  vpc_id      = aws_vpc.sadcloud_vpc.id

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "RDP from anywhere"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# 3. Vulnerable EC2 Instance (Free Tier Eligible t3.micro)
# Dynamically queries AWS EC2 for the latest Amazon Linux 2023 AMI
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }
}

resource "aws_instance" "sadcloud_ec2" {
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.sadcloud_subnet.id
  vpc_security_group_ids = [aws_security_group.sadcloud_vulnerable_sg.id]

  tags = {
    Name = "DriftWatch-Vulnerable-EC2"
  }
}

# 4. Vulnerable S3 Bucket (No Encryption, Public Access Block Disabled)
resource "random_id" "bucket_id" {
  byte_length = 4
}

resource "aws_s3_bucket" "sadcloud_vulnerable_bucket" {
  bucket = "driftwatch-exposed-data-${random_id.bucket_id.hex}"
}

resource "aws_s3_bucket_public_access_block" "public_access" {
  bucket = aws_s3_bucket.sadcloud_vulnerable_bucket.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# 5. Vulnerable IAM Policy (Full Admin Access)
resource "aws_iam_policy" "sadcloud_overly_permissive" {
  name        = "sadcloud-overly-permissive-policy"
  description = "Intentionally vulnerable admin policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = "*"
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}