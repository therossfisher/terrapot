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

data "aws_caller_identity" "current" {}

resource "aws_instance" "cloud_siem" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  iam_instance_profile   = aws_iam_instance_profile.cloud_siem_profile.name
  key_name               = aws_key_pair.cloud_siem_key.key_name
  vpc_security_group_ids = [aws_security_group.cloud_siem_sg.id]
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

    enable_thinkst_canary            = var.enable_thinkst_canary
    thinkst_canary_access_key_id     = var.thinkst_canary_access_key_id
    thinkst_canary_secret_access_key = var.thinkst_canary_secret_access_key

    enable_diy_canary            = var.enable_diy_canary
    diy_canary_access_key_id     = var.enable_diy_canary ? aws_iam_access_key.canary_decoy[0].id : ""
    diy_canary_secret_access_key = var.enable_diy_canary ? aws_iam_access_key.canary_decoy[0].secret : ""
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
  # checkov:skip=CKV_AWS_144:Ephemeral bucket (force_destroy), torn down every session — no durable data to replicate
  # checkov:skip=CKV_AWS_21:Ephemeral bucket, short single-session lifecycle — versioning not meaningful here
  # checkov:skip=CKV_AWS_18:This bucket is itself the log destination; access logging would require a second bucket for marginal value
  # checkov:skip=CKV2_AWS_62:No event-driven automation consumes this bucket currently — future feature, not in scope
  # checkov:skip=CKV2_AWS_61:Ephemeral bucket, force_destroy every session — no long-term objects requiring lifecycle rules
  bucket        = var.bucket_name
  force_destroy = true

  tags = {
    Name = "cloud-siem-logs"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloud_siem_logs_encryption" {
  bucket = aws_s3_bucket.cloud_siem_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
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

  tags = {
    Name = "cloud-siem-sg"
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
  security_group_id = aws_security_group.cloud_siem_sg.id
}

resource "aws_security_group_rule" "admin_ssh" {
  type              = "ingress"
  description       = "Real admin SSH"
  from_port         = var.admin_ssh_port
  to_port           = var.admin_ssh_port
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.cloud_siem_sg.id
}

# checkov:skip=CKV_AWS_260:Intentional honeypot bait — isc-agent must be reachable on port 80 to attract web scanners
resource "aws_security_group_rule" "web_honeypot" {
  type              = "ingress"
  description       = "Web honeypot"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.cloud_siem_sg.id
}

# checkov:skip=CKV_AWS_382:Instance requires unrestricted outbound for Docker image pulls, S3 log sync, and DShield/ISC reporting
resource "aws_security_group_rule" "allow_all_egress" {
  type              = "egress"
  description       = "Allow all outbound"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.cloud_siem_sg.id
}

resource "aws_security_group_rule" "grafana" {
  count = var.enable_grafana ? 1 : 0

  description       = "Grafana dashboard access"
  type              = "ingress"
  from_port         = var.grafana_port
  to_port           = var.grafana_port
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.cloud_siem_sg.id
}

resource "aws_security_group_rule" "grafana_https" {
  count = var.grafana_domain != "" ? 1 : 0

  description       = "Grafana HTTPS via reverse proxy"
  type              = "ingress"
  from_port         = 443
  to_port           = 443
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
      },
      {
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = aws_s3_bucket.cloud_siem_logs.arn
      }
    ]
  })
}

resource "aws_iam_instance_profile" "cloud_siem_profile" {
  name = "cloud-siem-instance-profile"
  role = aws_iam_role.cloud_siem_ec2_role.name
}

# --- a DIY Canary: zero-permission decoy IAM user ---
resource "aws_iam_user" "canary_decoy" {
  # checkov:skip=CKV_AWS_273:Not a real user account — this is a zero-permission decoy identity for the canary/honeytoken tripwire, SSO is not applicable
  count = var.enable_diy_canary ? 1 : 0
  name  = "svc-backup-automation" # a boring name with some plausible deniability
}

resource "aws_iam_access_key" "canary_decoy" {
  count = var.enable_diy_canary ? 1 : 0
  user  = aws_iam_user.canary_decoy[0].name
}
# NOTE: no aws_iam_user_policy or policy attachment resource at all —
# that's what makes this a zero-permission user. Nothing to attach.

# --- SNS topic for canary alerts ---
resource "aws_sns_topic" "canary_alerts" {
  #checkov:skip=CKV_AWS_26:Alert payload is CloudTrail metadata only, no sensitive data. AWS-managed KMS key can't grant EventBridge; CMK not justified for this content.
  count = var.enable_diy_canary ? 1 : 0
  name  = "cloud-siem-canary-alerts"
}

resource "aws_sns_topic_subscription" "canary_alerts_email" {
  count     = var.enable_diy_canary ? 1 : 0
  topic_arn = aws_sns_topic.canary_alerts[0].arn
  protocol  = "email"
  endpoint  = var.canary_alert_email
}

# --- EventBridge rule: fire on ANY API CALL made by decoy user ---
resource "aws_cloudwatch_event_rule" "canary_tripwire" {
  count       = var.enable_diy_canary ? 1 : 0
  name        = "cloud-siem-canary-tripwire"
  description = "Fires when the decoy IAM user makes any AWS API call"

  event_pattern = jsonencode({
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      userIdentity = {
        type     = ["IAMUser"]
        userName = [aws_iam_user.canary_decoy[0].name]
      }
    }
  })
}

# --- CloudTrail: required for EventBridge to receive "AWS API Call via CloudTrail" events at all ---
resource "aws_s3_bucket_policy" "cloud_siem_trail_bucket_policy" {
  count  = var.enable_diy_canary ? 1 : 0
  bucket = aws_s3_bucket.cloud_siem_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.cloud_siem_logs.arn
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.cloud_siem_logs.arn}/cloudtrail-logs/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" }
        }
      }
    ]
  })
}

resource "aws_cloudtrail" "cloud_siem_trail" {
  # checkov:skip=CKV_AWS_67:Single-region trail is a deliberate cost decision made to keep spend low
  # checkov:skip=CKV_AWS_35:Customer-managed KMS key has ongoing cost not justified for this project's scope; default protections apply
  # checkov:skip=CKV_AWS_252:Redundant with existing canary EventBridge->SNS alerting; a second "log delivered" notification adds noise not signal
  # checkov:skip=CKV2_AWS_10:CloudWatch Logs ingestion adds ongoing cost; raw logs already queried directly from S3
  count                         = var.enable_diy_canary ? 1 : 0
  name                          = "cloud-siem-canary-trail"
  s3_bucket_name                = aws_s3_bucket.cloud_siem_logs.id
  s3_key_prefix                 = "cloudtrail-logs"
  include_global_service_events = true
  is_multi_region_trail         = false
  enable_logging                = true
  enable_log_file_validation    = true # free integrity check — detects tampering of delivered log files

  depends_on = [aws_s3_bucket_policy.cloud_siem_trail_bucket_policy]
}

resource "aws_cloudwatch_event_target" "canary_to_sns" {
  count     = var.enable_diy_canary ? 1 : 0
  rule      = aws_cloudwatch_event_rule.canary_tripwire[0].name
  target_id = "canary-sns-alert"
  arn       = aws_sns_topic.canary_alerts[0].arn
}

# --- Permission for EventBridge to actually publish to the SNS topic ---
resource "aws_sns_topic_policy" "canary_alerts_policy" {
  count = var.enable_diy_canary ? 1 : 0
  arn   = aws_sns_topic.canary_alerts[0].arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublish"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.canary_alerts[0].arn
    }]
  })

}

resource "aws_ssm_parameter" "dshield_userid" {
  #checkov:skip=CKV_AWS_337:Using AWS-managed SSM key (aws/ssm), not a customer-managed CMK — CMK adds $1/mo per key, not justified for this scope. Default key still encrypts at rest via KMS
  name  = "/cloud-siem/dshield_userid"
  type  = "SecureString"
  value = var.dshield_userid
}

resource "aws_ssm_parameter" "dshield_authkey" {
  #checkov:skip=CKV_AWS_337:Same as dshield_userid — AWS-managed key sufficient, CMK cost not justified.
  name  = "/cloud-siem/dshield_authkey"
  type  = "SecureString"
  value = var.dshield_authkey
}

resource "aws_ssm_parameter" "grafana_admin_password" {
  #checkov:skip=CKV_AWS_337:Same as dshield_userid — AWS-managed key sufficient, CMK cost not justified.
  name  = "/cloud-siem/grafana_admin_password"
  type  = "SecureString"
  value = var.grafana_admin_password
}

resource "aws_iam_role_policy" "cloud_siem_ssm_policy" {
  name = "cloud-siem-ssm-read"
  role = aws_iam_role.cloud_siem_ec2_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["ssm:GetParameter", "ssm:GetParametersByPath"]
        Resource = [
          aws_ssm_parameter.dshield_userid.arn,
          aws_ssm_parameter.dshield_authkey.arn,
          aws_ssm_parameter.grafana_admin_password.arn
        ]
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = "arn:aws:kms:${var.aws_region}:${data.aws_caller_identity.current.account_id}:alias/aws/ssm"
      }
    ]
  })
}

resource "aws_iam_role_policy" "cloud_siem_route53_policy" {
  count = var.grafana_domain != "" ? 1 : 0

  name = "cloud-siem-route53-dns01"
  role = aws_iam_role.cloud_siem_ec2_role.id

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
      }
    ]
  })
}
