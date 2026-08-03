variable "bucket_arn" {
  description = "ARN of the terrapot log bucket, for scoping S3 permissions"
  type        = string
}

variable "aws_region" {
  description = "AWS region, for building the SSM KMS key ARN"
  type        = string
}

variable "account_id" {
  description = "AWS account ID, for building the SSM KMS key ARN"
  type        = string
}

variable "dshield_userid" {
  description = "DShield user ID, stored in SSM"
  type        = string
}

variable "dshield_authkey" {
  description = "DShield auth key, stored in SSM"
  type        = string
  sensitive   = true
}

variable "grafana_admin_password" {
  description = "Grafana admin password, stored in SSM"
  type        = string
  sensitive   = true
}

variable "grafana_domain" {
  description = "If set, grants Route53 DNS-01 permissions for Let's Encrypt"
  type        = string
  default     = ""
}

variable "route53_hosted_zone_id" {
  description = "Route53 hosted zone ID, required only when grafana_domain is set"
  type        = string
  default     = ""
}

variable "threat_intel_loki_secret_arns" {
  description = "loki_push_secret_arn from the threat_intel module, passed as a list so it's empty when the module is off"
  type        = list(string)
  default     = []
}