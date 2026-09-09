variable "subscription_id" {
  description = "Target Azure subscription id."
  type        = string
}

variable "github_repository" {
  description = "GitHub repo allowed to authenticate via OIDC, as \"org/repo\" (e.g. jalcalaroot/prowler-multicloud-reporter)."
  type        = string
}

variable "github_subject_prefix" {
  description = "Override the OIDC subject prefix if your GitHub account/org has subject-claim customization enabled (Settings -> Actions -> General) -- Azure's federated credential subject is an EXACT string match (no wildcard like AWS's StringLike), so this hits harder here than on the AWS side. Confirmed for real on 2026-09-08: this account presents 'repo:<org>@<org-id>/<repo>@<repo-id>:...' (numeric IDs) instead of the plain name -- check `gh api repos/<org>/<repo>/actions/oidc/customization/sub` if azure/login fails with AADSTS700213 despite a seemingly-correct federated credential. Also re-check this after renaming the GitHub repo -- the repo id stays stable but the name segment embedded in the subject updates to the new name. Leave empty for the plain \"repo:<github_repository>\" default most accounts use."
  type        = string
  default     = ""
}

variable "location" {
  description = "Azure region. Defaults to eastus -- confirmed for real across multiple applies (2026-09-06 through 2026-09-08) to avoid the \"Allowed locations\" governance-policy block that eastus2 hit on this account (see infra/azure/README.md's policy-exemption story, and CLAUDE.md). Switch to eastus2 (or anywhere else) only if your own subscription's governance policy requires it."
  type        = string
  default     = "eastus"
}

variable "resource_group_name" {
  description = "Resource group created to hold everything this tool needs. Kept dedicated (not the shared jalcalaroot RG) since this is a standalone tool, not part of the network/VM infra."
  type        = string
  default     = "rg-prowler-multicloud-agent"
}

variable "base_name" {
  description = "Short prefix for generated resource names (the storage account)."
  type        = string
  default     = "prowlerma"
}

# ---------------------------------------------------------------------------
# Reports storage (Blob equivalent of infra/aws's S3 bucket)
# ---------------------------------------------------------------------------
variable "enable_reports_storage" {
  description = "Create a private Blob Storage container for publishing reports as time-limited SAS-token links."
  type        = bool
  default     = true
}

variable "storage_account_name" {
  description = "Storage account name. Leave empty to auto-generate (storage account names must be globally unique, lowercase, 3-24 chars, no hyphens)."
  type        = string
  default     = ""
}

variable "reports_container_name" {
  description = "Blob container name for published reports."
  type        = string
  default     = "reports"
}

variable "reports_retention_days" {
  description = "Auto-delete published reports (and the findings history alongside them) after this many days via a lifecycle policy -- same reasoning as infra/aws: real vulnerability data about a real subscription shouldn't accumulate indefinitely."
  type        = number
  default     = 30
}
