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
  user_data = templatefile("${path.module}/user_data.sh.tftpl", {
    enable_dshield         = var.enable_dshield
    dshield_userid         = var.dshield_userid
    dshield_authkey        = var.dshield_authkey
    grafana_admin_user     = var.grafana_admin_user
    grafana_admin_password = var.grafana_admin_password
    enable_grafana         = var.enable_grafana
    bucket_name            = var.bucket_name

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
  count                         = var.enable_diy_canary ? 1 : 0
  name                          = "cloud-siem-canary-trail"
  s3_bucket_name                = aws_s3_bucket.cloud_siem_logs.id
  s3_key_prefix                 = "cloudtrail-logs"
  include_global_service_events = true
  is_multi_region_trail         = false
  enable_logging                = true

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

