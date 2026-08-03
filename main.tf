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

data "aws_caller_identity" "current" {}

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

module "networking" {
  source = "./modules/networking"

  admin_ssh_port = var.admin_ssh_port
  enable_grafana = var.enable_grafana
  grafana_port   = var.grafana_port
  grafana_domain = var.grafana_domain
}

module "canary" {
  count  = var.enable_diy_canary ? 1 : 0
  source = "./modules/canary"

  bucket_id          = aws_s3_bucket.terrapot_logs.id
  bucket_arn         = aws_s3_bucket.terrapot_logs.arn
  canary_alert_email = var.canary_alert_email
  account_id         = data.aws_caller_identity.current.account_id
}

module "threat_intel" {
  count  = var.enable_threat_intel ? 1 : 0
  source = "./modules/threat_intel"

  bucket_id         = aws_s3_bucket.terrapot_logs.id
  bucket_arn        = aws_s3_bucket.terrapot_logs.arn
  account_id        = data.aws_caller_identity.current.account_id
  aws_region        = var.aws_region
  abuseipdb_api_key = var.abuseipdb_api_key
  grafana_domain    = var.grafana_domain
}

module "iam" {
  source = "./modules/iam"

  bucket_arn             = aws_s3_bucket.terrapot_logs.arn
  aws_region             = var.aws_region
  account_id             = data.aws_caller_identity.current.account_id
  dshield_userid         = var.dshield_userid
  dshield_authkey        = var.dshield_authkey
  grafana_admin_password = var.grafana_admin_password
  grafana_domain         = var.grafana_domain
  route53_hosted_zone_id = var.route53_hosted_zone_id

  threat_intel_loki_secret_arns = module.threat_intel[*].loki_push_secret_arn
}

resource "aws_instance" "terrapot" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  iam_instance_profile   = module.iam.instance_profile_name
  key_name               = aws_key_pair.terrapot_key.key_name
  vpc_security_group_ids = [module.networking.security_group_id]
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

resource "aws_eip" "web_honeypot" {
  count    = var.enable_web_honeypot_routing ? 1 : 0
  instance = aws_instance.terrapot.id
  domain   = "vpc"

  tags = {
    Name = "terrapot-web-honeypot-eip"
  }
}