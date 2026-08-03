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
        Resource = "${var.bucket_arn}/*"
      },
      {
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = var.bucket_arn
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
        ], var.threat_intel_loki_secret_arns)
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = "arn:aws:kms:${var.aws_region}:${var.account_id}:alias/aws/ssm"
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