output "decoy_access_key_id" {
  description = "Access key ID for the decoy IAM user, planted as bait in the honeypot's fake credentials file"
  value       = aws_iam_access_key.canary_decoy.id
}

output "decoy_access_key_secret" {
  description = "Secret access key for the decoy IAM user, planted as bait in the honeypot's fake credentials file"
  value       = aws_iam_access_key.canary_decoy.secret
  sensitive   = true
}