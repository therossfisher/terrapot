output "instance_public_ip" {
  description = "Public IP address of the terrapot EC2 instance"
  value       = aws_instance.terrapot.public_ip
}

output "instance_public_dns" {
  description = "Public DNS name of the terrapot EC2 instance"
  value       = aws_instance.terrapot.public_dns
}

output "s3_bucket_name" {
  description = "Name of the S3 bucket for log storage"
  value       = aws_s3_bucket.terrapot_logs.bucket
}

output "web_honeypot_eip" {
  description = "Stable public IP for manual CloudFront origin config (Phase 8). Null unless enable_web_honeypot_routing = true. See README."
  value       = var.enable_web_honeypot_routing ? aws_eip.web_honeypot[0].public_ip : null
}