variable "project_id" {
  description = "GCP project this tool runs against. Kept dedicated (not a shared project) -- same reasoning as infra/azure's resource_group_name: this is a standalone tool, not part of a bigger network/VM infra project."
  type        = string
}

variable "region" {
  description = "GCP region for the reports bucket and Workload Identity Pool."
  type        = string
  default     = "us-central1"
}

variable "github_repository" {
  description = "GitHub repo allowed to authenticate via Workload Identity Federation, as \"org/repo\" (e.g. jalcalaroot/prowler-multicloud-reporter)."
  type        = string
}

variable "github_repository_id" {
  description = "The GitHub repo's own immutable numeric id (find it with `gh api repos/<org>/<repo> --jq .id`). If set, the Workload Identity Pool provider's attribute_condition matches on this instead of the repo name -- confirmed for real on 2026-09-08 (see CLAUDE.md) that a GitHub repo rename breaks AWS's/Azure's name-based OIDC trust and needs a manual Terraform re-apply to fix; matching GCP's condition on the stable repository_id instead means a future rename here needs no re-apply at all. Leave empty to match on github_repository's name instead (simpler, but breaks on rename like the other two clouds do)."
  type        = string
  default     = ""
}

variable "service_account_id" {
  description = "Service account id (the part before @<project>.iam.gserviceaccount.com) that GitHub Actions impersonates via Workload Identity Federation -- no static key ever created for it."
  type        = string
  default     = "prowler-reporter-ci"
}

variable "enable_reports_bucket" {
  description = "Create a private GCS bucket for publishing reports as time-limited V4 signed links (the GCP-hosted equivalent of infra/aws's S3 bucket / infra/azure's Blob container)."
  type        = bool
  default     = true
}

variable "reports_bucket_name" {
  description = "GCS bucket name for published reports. Leave empty to default to \"<service_account_id>-reports-<project_id>\" (GCS bucket names are globally unique across all of GCP)."
  type        = string
  default     = ""
}

variable "reports_retention_days" {
  description = "Auto-delete published reports (and the findings history alongside them) after this many days via a lifecycle rule -- same reasoning as infra/aws and infra/azure: real vulnerability data about a real project shouldn't accumulate indefinitely."
  type        = number
  default     = 30
}
