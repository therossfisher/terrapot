resource "aws_dynamodb_table" "threat_intel_lookups" {
  name         = "terrapot-threat-intel-lookups"
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
  name = "terrapot-threat-intel-lambda-role"

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
  name = "terrapot-threat-intel-lambda-dynamodb"
  role = aws_iam_role.threat_intel_lambda.name

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
        Resource = aws_dynamodb_table.threat_intel_lookups.arn
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "threat_intel_lambda_basic_execution" {
  role       = aws_iam_role.threat_intel_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_ssm_parameter" "abuseipdb_api_key" {
  #checkov:skip=CKV_AWS_337:Using AWS-managed SSM key (aws/ssm), not a customer-managed CMK — CMK adds $1/mo per key, not justified for this scope. Default key still encrypts at rest via KMS
  name  = "/terrapot/abuseipdb_api_key"
  type  = "SecureString"
  value = var.abuseipdb_api_key
}

resource "random_password" "loki_push_secret" {
  length  = 32
  special = false
}

resource "aws_ssm_parameter" "loki_push_secret" {
  #checkov:skip=CKV_AWS_337:Using AWS-managed SSM key (aws/ssm), not a customer-managed CMK, CMK cost not justified.
  name  = "/terrapot/loki_push_secret"
  type  = "SecureString"
  value = random_password.loki_push_secret.result
}

resource "aws_iam_role_policy" "threat_intel_lambda_ssm" {
  name = "terrapot-threat-intel-lambda-ssm"
  role = aws_iam_role.threat_intel_lambda.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["ssm:GetParameter", "ssm:GetParametersByPath"]
        Resource = [
          aws_ssm_parameter.abuseipdb_api_key.arn,
          aws_ssm_parameter.loki_push_secret.arn
        ]
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = "arn:aws:kms:${var.aws_region}:${var.account_id}:alias/aws/ssm"
      }
    ]
  })
}

resource "aws_iam_role_policy" "threat_intel_lambda_s3" {
  name = "terrapot-threat-intel-lambda-s3"
  role = aws_iam_role.threat_intel_lambda.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "${var.bucket_arn}/*"
      }
    ]
  })
}

data "archive_file" "threat_intel_lambda" {
  type        = "zip"
  source_dir  = "${path.module}/../../lambda_functions/threat_intel"
  output_path = "${path.module}/../../lambda_functions/threat_intel.zip"
}

resource "aws_lambda_function" "threat_intel" {
  function_name    = "terrapot-threat-intel"
  role             = aws_iam_role.threat_intel_lambda.arn
  handler          = "handler.handler"
  runtime          = "python3.12"
  filename         = data.archive_file.threat_intel_lambda.output_path
  source_code_hash = data.archive_file.threat_intel_lambda.output_base64sha256
  timeout          = 30

  environment {
    variables = {
      DYNAMODB_TABLE        = aws_dynamodb_table.threat_intel_lookups.name
      ABUSEIPDB_SSM_PARAM   = aws_ssm_parameter.abuseipdb_api_key.name
      LOKI_PUSH_URL         = "https://${var.grafana_domain}/loki/push"
      LOKI_SECRET_SSM_PARAM = aws_ssm_parameter.loki_push_secret.name
    }
  }
}

resource "aws_lambda_permission" "allow_s3" {
  statement_id  = "AllowS3Invoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.threat_intel.function_name
  principal     = "s3.amazonaws.com"
  source_arn    = var.bucket_arn
}

resource "aws_s3_bucket_notification" "threat_intel_trigger" {
  bucket = var.bucket_id

  lambda_function {
    lambda_function_arn = aws_lambda_function.threat_intel.arn
    events              = ["s3:ObjectCreated:*"]
  }

  depends_on = [aws_lambda_permission.allow_s3]
}