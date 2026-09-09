output "role_arn" {
  description = "Set this as the AWS_ROLE_ARN repo variable in GitHub Actions."
  value       = aws_iam_role.ci.arn
}

output "reports_bucket_name" {
  description = "Set this as the S3_REPORTS_BUCKET repo variable in GitHub Actions to enable link-based report delivery."
  value       = var.enable_reports_bucket ? aws_s3_bucket.reports[0].bucket : null
}
