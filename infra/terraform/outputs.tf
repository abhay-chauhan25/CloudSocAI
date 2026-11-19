output "account_id" {
  value = local.account_id
}

output "region" {
  value = var.region
}

output "trail_name" {
  value = aws_cloudtrail.lab.name
}

output "trail_bucket" {
  value = aws_s3_bucket.trail_logs.id
}

output "reader_role_arn" {
  value = aws_iam_role.reader.arn
}

output "denied_role_arn" {
  value = aws_iam_role.denied.arn
}

output "open_security_group_id" {
  value = aws_security_group.open_ssh.id
}

output "unblocked_bucket" {
  value = aws_s3_bucket.unblocked.id
}

output "reader_profile" {
  description = "Add to ~/.aws/config, replacing <your-admin-profile> with the profile you ran Terraform with."
  value       = <<-EOT
    [profile cloudsoc-reader]
    role_arn = ${aws_iam_role.reader.arn}
    source_profile = <your-admin-profile>
    region = ${var.region}
  EOT
}
