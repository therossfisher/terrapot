variable "bucket_id" {
  type = string
}

variable "bucket_arn" {
  type = string
}

variable "account_id" {
  type = string
}

variable "aws_region" {
  type = string
}

variable "abuseipdb_api_key" {
  type      = string
  sensitive = true
}

variable "grafana_domain" {
  type = string
}