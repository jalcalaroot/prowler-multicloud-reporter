data "aws_caller_identity" "current" {}

# Most accounts already have this from any other repo using GitHub Actions
# OIDC -- AWS allows only one provider per URL per account, so the default
# (create_oidc_provider = false) looks it up instead of creating a duplicate.
data "aws_iam_openid_connect_provider" "github" {
  count = var.create_oidc_provider ? 0 : 1
  url   = "https://token.actions.githubusercontent.com"
}

resource "aws_iam_openid_connect_provider" "github" {
  count           = var.create_oidc_provider ? 1 : 0
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"] # GitHub's OIDC root CA thumbprint
}

locals {
  oidc_provider_arn     = var.create_oidc_provider ? aws_iam_openid_connect_provider.github[0].arn : data.aws_iam_openid_connect_provider.github[0].arn
  account_id            = data.aws_caller_identity.current.account_id
  reports_bucket_name   = var.reports_bucket_name != "" ? var.reports_bucket_name : "${var.role_name}-reports-${local.account_id}"
  github_subject_prefix = var.github_subject_prefix != "" ? var.github_subject_prefix : "repo:${var.github_repository}"
}

data "aws_iam_policy_document" "trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [local.oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    # Any ref/branch of this repo can assume the role -- tighten to
    # "<prefix>:ref:refs/heads/main" if this should only run from main.
    #
    # github_subject_prefix exists because some GitHub accounts (confirmed
    # for real on this one, 2026-09-06: AssumeRoleWithWebIdentity failed
    # with a plain "repo:org/repo" prefix) have OIDC subject-claim
    # customization enabled (Settings -> Actions -> General, or check via
    # `gh api repos/<org>/<repo>/actions/oidc/customization/sub`), which
    # replaces the org/repo names with their immutable numeric IDs in the
    # actual token GitHub issues. Check that API response before assuming
    # the plain-name default below is what your account actually sends.
    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["${local.github_subject_prefix}:*"]
    }
  }
}

resource "aws_iam_role" "ci" {
  name               = var.role_name
  assume_role_policy = data.aws_iam_policy_document.trust.json
}

# Read-only cloud coverage for Prowler -- deliberately not AdministratorAccess.
resource "aws_iam_role_policy_attachment" "security_audit" {
  role       = aws_iam_role.ci.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_role_policy_attachment" "view_only" {
  role       = aws_iam_role.ci.name
  policy_arn = "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"
}

# Private bucket for publishing reports as time-limited presigned links --
# an alternative to email for a "final client" who just wants a URL. Never
# made public: real vulnerability findings shouldn't sit indefinitely
# discoverable on the open internet just because a link is convenient.
# Uploading the normalized findings JSON alongside the HTML reports (done by
# scripts/publish_reports.py) also builds a per-run history for free -- the
# seed of the "persistent findings store" phase-2 idea, not a separate DB.
resource "aws_s3_bucket" "reports" {
  count  = var.enable_reports_bucket ? 1 : 0
  bucket = local.reports_bucket_name
}

resource "aws_s3_bucket_public_access_block" "reports" {
  count                   = var.enable_reports_bucket ? 1 : 0
  bucket                  = aws_s3_bucket.reports[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "reports" {
  count  = var.enable_reports_bucket ? 1 : 0
  bucket = aws_s3_bucket.reports[0].id
  rule {
    id     = "expire-old-runs"
    status = "Enabled"
    filter {}
    expiration {
      days = var.reports_retention_days
    }
  }
}

data "aws_iam_policy_document" "s3_reports" {
  count = var.enable_reports_bucket ? 1 : 0
  statement {
    effect    = "Allow"
    actions   = ["s3:PutObject", "s3:GetObject"]
    resources = ["${aws_s3_bucket.reports[0].arn}/*"]
  }
}

resource "aws_iam_role_policy" "s3_reports" {
  count  = var.enable_reports_bucket ? 1 : 0
  name   = "s3-reports-publish"
  role   = aws_iam_role.ci.id
  policy = data.aws_iam_policy_document.s3_reports[0].json
}
