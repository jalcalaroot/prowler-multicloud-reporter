locals {
  reports_bucket_name = var.reports_bucket_name != "" ? var.reports_bucket_name : "${var.service_account_id}-reports-${var.project_id}"

  # Matching on the repo's immutable numeric id (when given) instead of its
  # name means a future GitHub repo rename never breaks this trust the way
  # it broke AWS's/Azure's OIDC trust on 2026-09-08 (see CLAUDE.md) -- those
  # needed a manual Terraform re-apply after the rename; this doesn't.
  attribute_condition = var.github_repository_id != "" ? "assertion.repository_id == \"${var.github_repository_id}\"" : "assertion.repository == \"${var.github_repository}\""
  principal_match_key  = var.github_repository_id != "" ? "attribute.repository_id" : "attribute.repository"
  principal_match_value = var.github_repository_id != "" ? var.github_repository_id : var.github_repository
}

# ---------------------------------------------------------------------------
# GitHub OIDC identity -- Workload Identity Federation, GCP's equivalent of
# AWS's OIDC-federated IAM role / Azure's federated Managed Identity. No
# service account key ever created or downloaded: GitHub's OIDC token is
# exchanged for short-lived GCP credentials at workflow run time.
# ---------------------------------------------------------------------------
resource "google_iam_workload_identity_pool" "github" {
  workload_identity_pool_id = "github-actions"
  display_name              = "GitHub Actions"
  description                = "Federated identity pool for GitHub Actions OIDC -- no static service account keys."
}

resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id         = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = "github-actions"
  display_name                       = "GitHub Actions OIDC"

  attribute_mapping = {
    "google.subject"           = "assertion.sub"
    "attribute.repository"     = "assertion.repository"
    "attribute.repository_id"  = "assertion.repository_id"
  }
  attribute_condition = local.attribute_condition

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

resource "google_service_account" "ci" {
  account_id   = var.service_account_id
  display_name = "GitHub Actions CI (prowler-multicloud-reporter)"
}

# Lets the matched GitHub Actions run impersonate this service account --
# the actual "trust policy" equivalent. Scoped to attribute.repository_id
# (or attribute.repository if no id given), matching the pool provider's
# own attribute_condition above.
resource "google_service_account_iam_member" "wif_binding" {
  service_account_id = google_service_account.ci.name
  role                = "roles/iam.workloadIdentityUser"
  member              = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/${local.principal_match_key}/${local.principal_match_value}"
}

# Self-impersonation grant, not a broader privilege -- this is what lets the
# service account sign GCS V4 URLs via the IAM Credentials API's signBlob
# (google-cloud-storage's generate_signed_url with impersonated_credentials)
# without ever holding a downloadable private key, the GCP equivalent of
# Azure's user-delegation SAS key.
resource "google_service_account_iam_member" "self_signer" {
  service_account_id = google_service_account.ci.name
  role                = "roles/iam.serviceAccountTokenCreator"
  member              = "serviceAccount:${google_service_account.ci.email}"
}

# Read-only cloud coverage for Prowler -- deliberately not roles/editor or
# roles/owner. Mirrors infra/aws's SecurityAudit+ViewOnlyAccess and
# infra/azure's Reader.
resource "google_project_iam_member" "viewer" {
  project = var.project_id
  role    = "roles/viewer"
  member  = "serviceAccount:${google_service_account.ci.email}"
}

# ---------------------------------------------------------------------------
# Reports storage -- GCS equivalent of infra/aws's private S3 bucket /
# infra/azure's private Blob container.
# ---------------------------------------------------------------------------
resource "google_storage_bucket" "reports" {
  count                       = var.enable_reports_bucket ? 1 : 0
  name                        = local.reports_bucket_name
  location                    = var.region
  force_destroy               = false
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced" # no anonymous public object access, ever

  lifecycle_rule {
    condition {
      age = var.reports_retention_days
    }
    action {
      type = "Delete"
    }
  }
}

resource "google_storage_bucket_iam_member" "ci_objects" {
  count  = var.enable_reports_bucket ? 1 : 0
  bucket = google_storage_bucket.reports[0].name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.ci.email}"
}
