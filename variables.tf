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
  description = "Port for real admin SSH access"
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

variable "enable_dshield" {
  description = "Enable DShield reporting to SANS ISC"
  type        = bool
  default     = false
}

variable "enable_grafana" {
  description = "Deploy Grafana dashboard alongside the honeypot"
  type        = bool
  default     = true
}

variable "grafana_admin_user" {
  description = "Admin username for Grafana"
  type        = string
  default     = "admin"
}

variable "grafana_admin_password" {
  description = "Admin password for Grafana"
  type        = string
  sensitive   = true
}

variable "dshield_userid" {
  description = "DShield user ID (required only if enable_dshield = true)"
  type        = string
}

variable "dshield_authkey" {
  description = "DShield auth key (required only if enable_dshield = true)"
  type        = string
  sensitive   = true
}
