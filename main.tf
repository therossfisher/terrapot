terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  backend "s3" {
    bucket       = "terrapot-tfstate-rossfisher-is-cool"
    key          = "terrapot/terraform.tfstate"
    region       = "us-east-1"
    encrypt      = true
    use_lockfile = true
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

module "canary" {
  count  = var.enable_diy_canary ? 1 : 0
  source = "./modules/canary"

  bucket_id          = aws_s3_bucket.terrapot_logs.id
  bucket_arn         = aws_s3_bucket.terrapot_logs.arn
  canary_alert_email = var.canary_alert_email
  account_id         = data.aws_caller_identity.current.account_id
}

data "aws_caller_identity" "current" {}

resource "aws_instance" "terrapot" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  iam_instance_profile   = aws_iam_instance_profile.terrapot_profile.name
  key_name               = aws_key_pair.terrapot_key.key_name
  vpc_security_group_ids = [aws_security_group.terrapot_sg.id]
  ebs_optimized          = true
  # Detailed monitoring is a paid CloudWatch feature not needed for this project's threat-intel goal; standard monitoring is sufficient.
  # checkov:skip=CKV_AWS_126:Detailed monitoring not required for honeypot threat-intel use case
  monitoring = false

  metadata_options {
    http_tokens = "required" # enforce IMDSv2 for security, blocks IMDSv1 SSRF-style attack path
  }

  root_block_device {
    encrypted = true # encrypts EBS root volume at rest using default AWS-managed KMS key
  }

  # checkov:skip=CKV_AWS_46:All values passed to user_data are variable references (var.*), not literal secrets; actual credentials are supplied at apply-time via terraform.tfvars, never committed
  user_data = templatefile("${path.module}/user_data.sh.tftpl", {
    aws_region         = var.aws_region
    enable_dshield     = var.enable_dshield
    grafana_admin_user = var.grafana_admin_user
    enable_grafana     = var.enable_grafana
    bucket_name        = var.bucket_name

    grafana_domain      = var.grafana_domain
    exclude_ip          = var.exclude_ip
    letsencrypt_email   = var.letsencrypt_email
    enable_threat_intel = var.enable_threat_intel

    enable_thinkst_canary            = var.enable_thinkst_canary
    thinkst_canary_access_key_id     = var.thinkst_canary_access_key_id
    thinkst_canary_secret_access_key = var.thinkst_canary_secret_access_key

    enable_diy_canary            = var.enable_diy_canary
    diy_canary_access_key_id     = var.enable_diy_canary ? module.canary[0].decoy_access_key_id : ""
    diy_canary_secret_access_key = var.enable_diy_canary ? module.canary[0].decoy_access_key_secret : ""
  })

  tags = {
    Name = "terrapot"
  }
}

resource "aws_key_pair" "terrapot_key" {
  key_name   = "terrapot-key"
  public_key = file(var.public_key_path)
}

resource "aws_s3_bucket" "terrapot_logs" {
  # checkov:skip=CKV_AWS_144:Ephemeral bucket (force_destroy), torn down every session — no durable data to replicate
  # checkov:skip=CKV_AWS_21:Ephemeral bucket, short single-session lifecycle — versioning not meaningful here
  # checkov:skip=CKV_AWS_18:This bucket is itself the log destination; access logging would require a second bucket for marginal value
  # checkov:skip=CKV2_AWS_61:Ephemeral bucket, force_destroy every session — no long-term objects requiring lifecycle rules
  bucket        = var.bucket_name
  force_destroy = true

  tags = {
    Name = "terrapot-logs"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "terrapot_logs_encryption" {
  bucket = aws_s3_bucket.terrapot_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}
resource "aws_s3_bucket_public_access_block" "terrapot_logs_block" {
  bucket = aws_s3_bucket.terrapot_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_security_group" "terrapot_sg" {
  name        = "terrapot-sg"
  description = "Security group for terrapot honeypot and admin access"

  tags = {
    Name = "terrapot-sg"
  }
}

# checkov:skip=CKV_AWS_24:Intentional honeypot bait — Cowrie must be reachable on port 22 to attract SSH attackers
resource "aws_security_group_rule" "cowrie_ssh" {
  type              = "ingress"
  description       = "Cowrie honeypot SSH bait"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.terrapot_sg.id
}

resource "aws_security_group_rule" "admin_ssh" {
  type              = "ingress"
  description       = "Real admin SSH"
  from_port         = var.admin_ssh_port
  to_port           = var.admin_ssh_port
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.terrapot_sg.id
}

# checkov:skip=CKV_AWS_260:Intentional honeypot bait — isc-agent must be reachable on port 80 to attract web scanners
resource "aws_security_group_rule" "web_honeypot" {
  type              = "ingress"
  description       = "Web honeypot"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.terrapot_sg.id
}

# checkov:skip=CKV_AWS_382:Instance requires unrestricted outbound for Docker image pulls, S3 log sync, and DShield/ISC reporting
resource "aws_security_group_rule" "allow_all_egress" {
  type              = "egress"
  description       = "Allow all outbound"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.terrapot_sg.id
}

resource "aws_security_group_rule" "grafana" {
  count = var.enable_grafana ? 1 : 0

  description       = "Grafana dashboard access"
  type              = "ingress"
  from_port         = var.grafana_port
  to_port           = var.grafana_port
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.terrapot_sg.id
}

resource "aws_security_group_rule" "grafana_https" {
  count = var.grafana_domain != "" ? 1 : 0

  description       = "Grafana HTTPS via reverse proxy"
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.terrapot_sg.id
}

resource "aws_iam_role" "terrapot_ec2_role" {
  name = "terrapot-ec2-role"

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

resource "aws_iam_role_policy" "terrapot_s3_policy" {
  name = "terrapot-s3-write"
  role = aws_iam_role.terrapot_ec2_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject"
        ]
        Resource = "${aws_s3_bucket.terrapot_logs.arn}/*"
      },
      {
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = aws_s3_bucket.terrapot_logs.arn
      }
    ]
  })
}

resource "aws_iam_instance_profile" "terrapot_profile" {
  name = "terrapot-instance-profile"
  role = aws_iam_role.terrapot_ec2_role.name
}

resource "aws_ssm_parameter" "dshield_userid" {
  #checkov:skip=CKV_AWS_337:Using AWS-managed SSM key (aws/ssm), not a customer-managed CMK — CMK adds $1/mo per key, not justified for this scope. Default key still encrypts at rest via KMS
  name  = "/terrapot/dshield_userid"
  type  = "SecureString"
  value = var.dshield_userid
}

resource "aws_ssm_parameter" "dshield_authkey" {
  #checkov:skip=CKV_AWS_337:Same as dshield_userid — AWS-managed key sufficient, CMK cost not justified.
  name  = "/terrapot/dshield_authkey"
  type  = "SecureString"
  value = var.dshield_authkey
}

resource "aws_ssm_parameter" "grafana_admin_password" {
  #checkov:skip=CKV_AWS_337:Same as dshield_userid — AWS-managed key sufficient, CMK cost not justified.
  name  = "/terrapot/grafana_admin_password"
  type  = "SecureString"
  value = var.grafana_admin_password
}

resource "random_password" "loki_push_secret" {
  count   = var.enable_threat_intel ? 1 : 0
  length  = 32
  special = false
}

resource "aws_ssm_parameter" "loki_push_secret" {
  count = var.enable_threat_intel ? 1 : 0
  #checkov:skip=CKV_AWS_337:Using AWS-managed SSM key (aws/ssm), not a customer-managed CMK, CMK cost not justified.
  name  = "/terrapot/loki_push_secret"
  type  = "SecureString"
  value = random_password.loki_push_secret[0].result
}

resource "aws_iam_role_policy" "terrapot_ssm_policy" {
  name = "terrapot-ssm-read"
  role = aws_iam_role.terrapot_ec2_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["ssm:GetParameter", "ssm:GetParametersByPath"]
        Resource = concat([
          aws_ssm_parameter.dshield_userid.arn,
          aws_ssm_parameter.dshield_authkey.arn,
          aws_ssm_parameter.grafana_admin_password.arn,
        ], aws_ssm_parameter.loki_push_secret[*].arn)

      },

      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = "arn:aws:kms:${var.aws_region}:${data.aws_caller_identity.current.account_id}:alias/aws/ssm"
      }
    ]
  })
}

resource "aws_iam_role_policy" "terrapot_route53_policy" {
  count = var.grafana_domain != "" ? 1 : 0

  name = "terrapot-route53-dns01"
  role = aws_iam_role.terrapot_ec2_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowChangeRecordSetsOnHostedZone"
        Effect   = "Allow"
        Action   = "route53:ChangeResourceRecordSets"
        Resource = "arn:aws:route53:::hostedzone/${var.route53_hosted_zone_id}"
      },
      {
        Sid      = "AllowGetChangeStatus"
        Effect   = "Allow"
        Action   = "route53:GetChange"
        Resource = "*"
      },
      {
        Sid      = "AllowListHostedZones"
        Effect   = "Allow"
        Action   = ["route53:ListHostedZones", "route53:ListHostedZonesByName"]
        Resource = "*"
      },
    ]
  })
}

resource "aws_eip" "web_honeypot" {
  count    = var.enable_web_honeypot_routing ? 1 : 0
  instance = aws_instance.terrapot.id
  domain   = "vpc"

  tags = {
    Name = "terrapot-web-honeypot-eip"
  }
}