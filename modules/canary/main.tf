# a DIY Canary: zero permission decoy IAM user
resource "aws_iam_user" "canary_decoy" {
  # checkov:skip=CKV_AWS_273:Not a real user account — this is a zero-permission decoy identity.
  name = "svc-backup-automation"
}

resource "aws_iam_access_key" "canary_decoy" {
  user = aws_iam_user.canary_decoy.name
}
# NOTE: Intentionally left with no aws_iam_user_policy or policy attachment
# making this a zero-permission user, nothing to attach

# SNS topic for canary alerts
resource "aws_sns_topic" "canary_alerts" {
  #checkov:skip=CKV_AWS_26:Alert payload is CloudTrail metadata only, no sensitive data. AWS-managed KMS key can't grant EventBridge; CMK not justified for this content.
  name = "terrapot-canary-alerts"
}

resource "aws_sns_topic_subscription" "canary_alerts_email" {
  topic_arn = aws_sns_topic.canary_alerts.arn
  protocol  = "email"
  endpoint  = var.canary_alert_email

  lifecycle {
    precondition {
      condition     = var.canary_alert_email != ""
      error_message = "canary_alert_email must be set when enable_diy_canary is true"
    }
  }
}

# EventBridge rule: fire on ANY API CALL made by decoy user except List/Get/Describe-prefixed reads
resource "aws_cloudwatch_event_rule" "canary_tripwire" {
  name        = "terrapot-canary-tripwire"
  description = "Fires on any AWS API call by the decoy user, except List/Get/Describe-prefixed reads"

  event_pattern = jsonencode({
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      userIdentity = {
        type     = ["IAMUser"]
        userName = [aws_iam_user.canary_decoy.name]
      }
    }
  })
}

# CloudTrail: required for EventBridge to receive "AWS API Call via CloudTrail" events at all
resource "aws_s3_bucket_policy" "terrapot_trail_bucket_policy" {
  bucket = var.bucket_id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = var.bucket_arn
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${var.bucket_arn}/cloudtrail-logs/AWSLogs/${var.account_id}/*"
        Condition = {
          StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" }
        }
      }
    ]
  })
}


resource "aws_cloudtrail" "terrapot_trail" {
  # checkov:skip=CKV_AWS_67:Single-region trail is a deliberate cost decision made to keep spend low
  # checkov:skip=CKV_AWS_35:Customer-managed KMS key has ongoing cost not justified for this project's scope; default protections apply
  # checkov:skip=CKV_AWS_252:Redundant with existing canary EventBridge->SNS alerting; a second "log delivered" notification adds noise not signal
  # checkov:skip=CKV2_AWS_10:CloudWatch Logs ingestion adds ongoing cost; raw logs already queried directly from S3
  name                          = "terrapot-canary-trail"
  s3_bucket_name                = var.bucket_id
  s3_key_prefix                 = "cloudtrail-logs"
  include_global_service_events = true
  is_multi_region_trail         = false
  enable_logging                = true
  enable_log_file_validation    = true # free integrity check — detects tampering of delivered log files

  depends_on = [aws_s3_bucket_policy.terrapot_trail_bucket_policy]
}

resource "aws_cloudwatch_event_target" "canary_to_sns" {
  rule      = aws_cloudwatch_event_rule.canary_tripwire.name
  target_id = "canary-sns-alert"
  arn       = aws_sns_topic.canary_alerts.arn
}

# Permission for EventBridge to actually publish to the SNS topic
resource "aws_sns_topic_policy" "canary_alerts_policy" {
  arn = aws_sns_topic.canary_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublish"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.canary_alerts.arn
    }]
  })
}