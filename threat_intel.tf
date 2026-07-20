# threat_intel.tf
# Phase 10 — threat intel enrichment (AbuseIPDB)
# Fully optional: gated behind enable_threat_intel, defaults to false.
# Skipping this feature entirely does not require any of these variables to be set.

resource "aws_dynamodb_table" "threat_intel_lookups" {
  count        = var.enable_threat_intel ? 1 : 0
  name         = "cloud-siem-threat-intel-lookups"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "src_ip"

  attribute {
    name = "src_ip"
    type = "S"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }
}

resource "aws_iam_role" "threat_intel_lambda" {
  count = var.enable_threat_intel ? 1 : 0
  name  = "cloud-siem-threat-intel-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "lambda.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "threat_intel_lambda_dynamodb" {
  count = var.enable_threat_intel ? 1 : 0
  name  = "cloud-siem-threat-intel-lambda-dynamodb"
  role  = aws_iam_role.threat_intel_lambda[0].name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem"
        ]
        Resource = aws_dynamodb_table.threat_intel_lookups[0].arn
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "threat_intel_lambda_basic_execution" {
  count      = var.enable_threat_intel ? 1 : 0
  role       = aws_iam_role.threat_intel_lambda[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_ssm_parameter" "abuseipdb_api_key" {
  count = var.enable_threat_intel ? 1 : 0
  #checkov:skip=CKV_AWS_337:Using AWS-managed SSM key (aws/ssm), not a customer-managed CMK — CMK adds $1/mo per key, not justified for this scope. Default key still encrypts at rest via KMS
  name  = "/cloud-siem/abuseipdb_api_key"
  type  = "SecureString"
  value = var.abuseipdb_api_key
}

resource "aws_iam_role_policy" "threat_intel_lambda_ssm" {
  count = var.enable_threat_intel ? 1 : 0
  name  = "cloud-siem-threat-intel-lambda-ssm"
  role  = aws_iam_role.threat_intel_lambda[0].name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["ssm:GetParameter", "ssm:GetParametersByPath"]
        Resource = [aws_ssm_parameter.abuseipdb_api_key[0].arn,
          aws_ssm_parameter.loki_push_secret[0].arn
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

resource "aws_iam_role_policy" "threat_intel_lambda_s3" {
  count = var.enable_threat_intel ? 1 : 0
  name  = "cloud-siem-threat-intel-lambda-s3"
  role  = aws_iam_role.threat_intel_lambda[0].name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "${aws_s3_bucket.cloud_siem_logs.arn}/*"
      }
    ]
  })
}

data "archive_file" "threat_intel_lambda" {
  count       = var.enable_threat_intel ? 1 : 0
  type        = "zip"
  source_dir  = "${path.module}/lambda_functions/threat_intel"
  output_path = "${path.module}/lambda_functions/threat_intel.zip"
}

resource "aws_lambda_function" "threat_intel" {
  count            = var.enable_threat_intel ? 1 : 0
  function_name    = "cloud-siem-threat-intel"
  role             = aws_iam_role.threat_intel_lambda[0].arn
  handler          = "handler.handler"
  runtime          = "python3.12"
  filename         = data.archive_file.threat_intel_lambda[0].output_path
  source_code_hash = data.archive_file.threat_intel_lambda[0].output_base64sha256
  timeout          = 30

  environment {
    variables = {
      DYNAMODB_TABLE        = aws_dynamodb_table.threat_intel_lookups[0].name
      ABUSEIPDB_SSM_PARAM   = aws_ssm_parameter.abuseipdb_api_key[0].name
      LOKI_PUSH_URL         = "https://${var.grafana_domain}/loki/push"
      LOKI_SECRET_SSM_PARAM = aws_ssm_parameter.loki_push_secret[0].name
    }
  }
}

resource "aws_lambda_permission" "allow_s3" {
  count         = var.enable_threat_intel ? 1 : 0
  statement_id  = "AllowS3Invoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.threat_intel[0].function_name
  principal     = "s3.amazonaws.com"
  source_arn    = aws_s3_bucket.cloud_siem_logs.arn
}

resource "aws_s3_bucket_notification" "threat_intel_trigger" {
  count  = var.enable_threat_intel ? 1 : 0
  bucket = aws_s3_bucket.cloud_siem_logs.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.threat_intel[0].arn
    events              = ["s3:ObjectCreated:*"]
  }

  depends_on = [aws_lambda_permission.allow_s3]
}