variable "admin_ssh_port" {
  description = "Port for real admin SSH access"
  type        = number
}

variable "enable_grafana" {
  description = "Whether to open the Grafana port for direct HTTP access"
  type        = bool
}

variable "grafana_port" {
  description = "Port for Grafana direct access, only opened when enable_grafana is true"
  type        = number
}

variable "grafana_domain" {
  description = "If set, opens port 443 for Grafana HTTPS via the nginx reverse proxy"
  type        = string
  default     = ""
}