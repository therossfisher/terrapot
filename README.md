# terrapot

A cloud-hosted, containerized threat intelligence platform: a live DShield/Cowrie honeypot on AWS, provisioned entirely as code, feeding a Grafana dashboard, with CI/CD security scanning and AWS-native threat detection layered on top.

**Live dashboard:** dashboard.therossfisher.xyz (migrating from a Raspberry Pi deployment — Pi remains live as an additional, geographically distinct sensor)

## Why This Exists

Small and mid-sized organizations can't afford commercial SIEM platforms ($20K–$200K/yr) but still need visibility into what's hitting their infrastructure. This project delivers a working version of that capability for roughly $15–20/month in AWS costs — real threat intelligence, real dashboards, real detection, at infrastructure cost.

## Status

**Phase 1 — Foundation: Complete**

Terraform provisions the full AWS foundation: EC2 instance, security groups, S3 log storage, and least-privilege IAM — fully reproducible from a clean clone.

## Architecture — Phase 1

- **EC2 (t3.micro)** — Ubuntu 22.04, resolved via a live AMI data source (not hardcoded), so the deployment always uses Canonical's current patched image
- **Security group**, modeled on real DShield/Cowrie architecture:
  - Port 22 → open to the internet — Cowrie honeypot bait
  - Port 80 → open to the internet — web honeypot bait
  - Port 12222 → real admin SSH (Cowrie internally redirects 22→2222 via iptables on the instance; 12222 is the actual management port, matching the existing Raspberry Pi sensor's config)
  - Port 3000 → Grafana (admin access; a separate, narrower public-dashboard sharing decision comes in Phase 4)
- **S3 bucket** for log storage, `force_destroy = true` so `terraform destroy` never leaves orphaned storage costs behind
- **IAM role + policy + instance profile** — the EC2 instance authenticates to AWS via a role, not a hardcoded access key. Policy grants only `s3:PutObject` / `s3:GetObject` on this bucket's ARN — no delete, no bucket-wide list, no admin actions

## Reproducing This

Requirements: an AWS account, Terraform installed, an SSH key pair.

```bash
git clone https://github.com/therossfisher/terrapot.git
cd terrapot
cp terraform.tfvars.example terraform.tfvars
# edit terraform.tfvars: your SSH public key path, a globally-unique S3 bucket name
terraform init
terraform plan
terraform apply
```

`terraform destroy` tears everything down cleanly — no manual cleanup, no leftover S3 storage charges.

## Cost

Roughly $7.50/month for the EC2 instance if run continuously (t3.micro, us-east-1, standard on-demand pricing). S3 and IAM are effectively free at this scale. Designed for a destroy/rebuild workflow — spin up to work on it, tear down when idle.

## Roadmap

- [x] Phase 1 — Terraform foundation (EC2, security groups, S3, IAM)
- [ ] Phase 2 — Docker + DShield sensor containerization, cloud-init automated provisioning
- [ ] Phase 3 — Python log processor + AbuseIPDB enrichment
- [ ] Phase 4 — Grafana dashboard
- [ ] Phase 5 — GitHub Actions CI/CD with Checkov security scanning
- [ ] Phase 6 — GuardDuty, CloudWatch, CloudTrail, SNS alerting
- [ ] Phase 7 — Documentation, architecture diagram, blog writeup

