terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
}

resource "aws_instance" "cloud_siem" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  iam_instance_profile   = aws_iam_instance_profile.cloud_siem_profile.name
  key_name               = aws_key_pair.cloud_siem_key.key_name
  vpc_security_group_ids = [aws_security_group.cloud_siem_sg.id]
  user_data = templatefile("${path.module}/user_data.sh.tftpl", {
    enable_dshield         = var.enable_dshield
    dshield_userid         = var.dshield_userid
    dshield_authkey        = var.dshield_authkey
    grafana_admin_user     = var.grafana_admin_user
    grafana_admin_password = var.grafana_admin_password
    enable_grafana         = var.enable_grafana
  })

  tags = {
    Name = "cloud_siem"
  }
}

resource "aws_key_pair" "cloud_siem_key" {
  key_name   = "cloud-siem-key"
  public_key = file(var.public_key_path)
}

resource "aws_s3_bucket" "cloud_siem_logs" {
  bucket        = var.bucket_name
  force_destroy = true

  tags = {
    Name = "cloud-siem-logs"
  }
}

resource "aws_s3_bucket_public_access_block" "cloud_siem_logs_block" {
  bucket = aws_s3_bucket.cloud_siem_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_security_group" "cloud_siem_sg" {
  name        = "cloud-siem-sg"
  description = "Security group for cloud-siem honeypot and admin access"

  ingress {
    description = "Cowrie honeypot SSH bait"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Real admin SSH"
    from_port   = var.admin_ssh_port
    to_port     = var.admin_ssh_port
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Web honeypot"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "cloud-siem-sg"
  }
}

resource "aws_security_group_rule" "grafana" {
  count = var.enable_grafana ? 1 : 0

  type              = "ingress"
  from_port         = var.grafana_port
  to_port           = var.grafana_port
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.cloud_siem_sg.id
}

resource "aws_iam_role" "cloud_siem_ec2_role" {
  name = "cloud-siem-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "cloud_siem_s3_policy" {
  name = "cloud-siem-s3-write"
  role = aws_iam_role.cloud_siem_ec2_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject"
        ]
        Resource = "${aws_s3_bucket.cloud_siem_logs.arn}/*"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "cloud_siem_profile" {
  name = "cloud-siem-instance-profile"
  role = aws_iam_role.cloud_siem_ec2_role.name
}