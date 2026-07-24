variable "bucket_id" {
  description = "ID of the S3 bucket used for CloudTrail log delivery"
  type        = string
}

variable "bucket_arn" {
  description = "ARN of the same S3 bucket, for IAM policy statements"
  type        = string
}

variable "canary_alert_email" {
  description = "Email address to receive canary tripwire alerts via SNS"
  type        = string
}

variable "account_id" {
  description = "AWS account ID, used to scope the CloudTrail bucket policy path"
  type        = string
}