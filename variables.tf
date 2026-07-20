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

variable "grafana_domain" {
  description = "Optional domain/subdomain for Grafana HTTPS access (e.g. grafana.yourdomain.com). Leave empty to skip HTTPS and access Grafana via http://<instance-ip>:3000 only."
  type        = string
  default     = ""
}

variable "route53_hosted_zone_id" {
  description = "Route53 hosted zone ID for grafana_domain's parent domain (required only if grafana_domain is set)"
  type        = string
  default     = ""
}

variable "letsencrypt_email" {
  description = "Contact email for Let's Encrypt certificate expiry notices (required only if grafana_domain is set)"
  type        = string
  default     = ""
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

variable "enable_diy_canary" {
  description = "Create a zero-permission IAM decoy user with EventBridge/SNS alerting"
  type        = bool
  default     = true
}

variable "canary_alert_email" {
  description = "Email address to receive canary trip-wire alerts via SNS"
  type        = string
  default     = "fisher.ross1776@gmail.com"
}

variable "enable_thinkst_canary" {
  description = "Deploy a Thinkst canarytokens.org AWS decoy key in Cowrie's filesystem (requires your own token)"
  type        = bool
  default     = false
}

variable "thinkst_canary_access_key_id" {
  description = "Access key ID from your own canarytokens.org AWS Keys token (required only if enable_thinkst_canary = true)"
  type        = string
  default     = ""
}

variable "thinkst_canary_secret_access_key" {
  description = "Secret access key from your own canarytokens.org AWS Keys token"
  type        = string
  default     = ""
  sensitive   = true
}

# Variables below this line require some additional AWS console setup beyond setting the variables, refer to README for details.
variable "enable_web_honeypot_routing" {
  description = "Allocate a stable Elastic IP for CloudFront path-based routing to the web honeypot (Phase 8). Off by default — no cost impact when false."
  type        = bool
  default     = false
}

variable "enable_threat_intel" {
  description = "Deploy threat intel enrichment (AbuseIPDB lookups on attacker IPs)"
  type        = bool
  default     = false
}

variable "abuseipdb_api_key" {
  description = "API key for AbuseIPDB threat intel lookups (required only if enable_threat_intel = true)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "exclude_ip" {
  description = "Optional IP address to exclude from all Grafana dashboard panels (e.g. your own home/admin IP, so testing traffic doesn't pollute the honeypot data)"
  type        = string
  default     = ""
}