output "security_group_id" {
  description = "ID of the terrapot security group, for attaching to the EC2 instance"
  value       = aws_security_group.terrapot_sg.id
}