variable "github_repository" {
  description = "GitHub repo allowed to assume this role via OIDC, as \"org/repo\" (e.g. jalcalaroot/prowler-multicloud-reporter)."
  type        = string
}

variable "github_subject_prefix" {
  description = "Override the OIDC subject prefix if your GitHub account/org has subject-claim customization enabled (Settings -> Actions -> General) -- check `gh api repos/<org>/<repo>/actions/oidc/customization/sub` if AssumeRoleWithWebIdentity fails with a \"Not authorized\" error despite a seemingly-correct trust policy. Leave empty for the plain \"repo:<github_repository>\" default most accounts use."
  type        = string
  default     = ""
}

variable "aws_region" {
  description = "Region the CI role is scoped to."
  type        = string
  default     = "us-east-1"
}

variable "role_name" {
  description = "Name of the IAM role GitHub Actions assumes."
  type        = string
  default     = "prowler-multicloud-agent-ci"
}

variable "create_oidc_provider" {
  description = "Create the GitHub Actions OIDC provider. Leave false if one already exists in this account (AWS allows only one per URL) -- most accounts running any GitHub Actions OIDC already have it."
  type        = bool
  default     = false
}

variable "enable_reports_bucket" {
  description = "Create a private S3 bucket for publishing reports as time-limited presigned links (an alternative/complement to email delivery)."
  type        = bool
  default     = true
}

variable "reports_bucket_name" {
  description = "S3 bucket name for published reports. Leave empty to default to \"<role_name>-reports-<account_id>\" (bucket names are globally unique across all AWS accounts, hence the account id suffix)."
  type        = string
  default     = ""
}

variable "reports_retention_days" {
  description = "Auto-delete published reports (and the findings history alongside them) after this many days. Findings are real vulnerability data about a real account -- don't let them accumulate indefinitely in a bucket."
  type        = number
  default     = 30
}
