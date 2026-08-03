resource "aws_security_group" "terrapot_sg" {
  name        = "terrapot-sg"
  description = "Security group for terrapot honeypot and admin access"

  tags = {
    Name = "terrapot-sg"
  }
}

# checkov:skip=CKV_AWS_24:Intentional honeypot bait — Cowrie must be reachable on port 22 to attract SSH attackers
resource "aws_security_group_rule" "cowrie_ssh" {
  type              = "ingress"
  description       = "Cowrie honeypot SSH bait"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.terrapot_sg.id
}

resource "aws_security_group_rule" "admin_ssh" {
  type              = "ingress"
  description       = "Real admin SSH"
  from_port         = var.admin_ssh_port
  to_port           = var.admin_ssh_port
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.terrapot_sg.id
}

# checkov:skip=CKV_AWS_260:Intentional honeypot bait — isc-agent must be reachable on port 80 to attract web scanners
resource "aws_security_group_rule" "web_honeypot" {
  type              = "ingress"
  description       = "Web honeypot"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.terrapot_sg.id
}

# checkov:skip=CKV_AWS_382:Instance requires unrestricted outbound for Docker image pulls, S3 log sync, and DShield/ISC reporting
resource "aws_security_group_rule" "allow_all_egress" {
  type              = "egress"
  description       = "Allow all outbound"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.terrapot_sg.id
}

resource "aws_security_group_rule" "grafana" {
  count = var.enable_grafana ? 1 : 0

  description       = "Grafana dashboard access"
  type              = "ingress"
  from_port         = var.grafana_port
  to_port           = var.grafana_port
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.terrapot_sg.id
}

resource "aws_security_group_rule" "grafana_https" {
  count = var.grafana_domain != "" ? 1 : 0

  description       = "Grafana HTTPS via reverse proxy"
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.terrapot_sg.id
}