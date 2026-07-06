output "instance_public_ip" {
  description = "Public IP address of the cloud-siem EC2 instance"
  value       = aws_instance.cloud_siem.public_ip
}

output "instance_public_dns" {
  description = "Public DNS name of the cloud-siem EC2 instance"
  value       = aws_instance.cloud_siem.public_dns
}

output "s3_bucket_name" {
  description = "Name of the S3 bucket for log storage"
  value       = aws_s3_bucket.cloud_siem_logs.bucket
}


