output "instance_profile_name" {
  description = "Name of the instance profile, for attaching to the EC2 instance"
  value       = aws_iam_instance_profile.terrapot_profile.name
}