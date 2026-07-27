output "loki_push_secret_arn" {
  value = aws_ssm_parameter.loki_push_secret.arn
}