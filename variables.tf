variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "us-east-1"
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.micro"
}

variable "public_key_path" {
  description = "Path to your SSH public key"
  type        = string
}

variable "admin_ssh_port" {
  description = "Port for real admin SSH access (post-DShield-install)"
  type        = number
  default     = 12222
}

variable "grafana_port" {
  description = "Port for Grafana dashboard"
  type        = number
  default     = 3000
}

variable "bucket_name" {
  description = "Globally unique S3 bucket name for log storage"
  type        = string
}