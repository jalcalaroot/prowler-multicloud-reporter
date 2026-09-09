output "workload_identity_provider" {
  description = "Set as the GCP_WORKLOAD_IDENTITY_PROVIDER repo variable in GitHub Actions (used by google-github-actions/auth)."
  value       = google_iam_workload_identity_pool_provider.github.name
}

output "service_account_email" {
  description = "Set as the GCP_SERVICE_ACCOUNT_EMAIL repo variable in GitHub Actions."
  value       = google_service_account.ci.email
}

output "reports_bucket_name" {
  description = "Set as the GCS_REPORTS_BUCKET repo variable to enable link-based report delivery."
  value       = var.enable_reports_bucket ? google_storage_bucket.reports[0].name : null
}
