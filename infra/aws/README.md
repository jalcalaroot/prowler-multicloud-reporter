# infra/aws

Creates the AWS resources this project needs to run for real: an IAM role that GitHub Actions assumes via OIDC (no static AWS keys as repo secrets), scoped to read-only cloud access (`SecurityAudit` + `ViewOnlyAccess`) -- and, optionally, a private S3 bucket for publishing reports as time-limited links. No Bedrock/AI permissions at all -- the AI summary ([llamafile](https://github.com/Mozilla-Ocho/llamafile)) runs entirely on the GitHub Actions runner, not against any cloud model.

Direct Terraform, no CI/PR pipeline around it -- this is a one-time bootstrap step per AWS account you point this tool at, not something that changes often enough to need one.

## Usage

```bash
cd infra/aws
terraform init
terraform apply -var="github_repository=<org>/<repo>"   # e.g. jalcalaroot/prowler-multicloud-reporter
```

Take the outputs and set them as **repo variables** (not secrets -- neither is sensitive) in GitHub: Settings -> Secrets and variables -> Actions -> Variables:
- `role_arn` -> `AWS_ROLE_ARN`. `scan.yml`'s AWS leg picks it up automatically once `use_sample_data` is set to `false`.
- `reports_bucket_name` -> `S3_REPORTS_BUCKET`. Enables the "Publish reports to S3" step in `scan.yml` (skipped entirely if this variable is empty).

## Parameters worth knowing about

- `create_oidc_provider` defaults to `false` because most AWS accounts already have a `token.actions.githubusercontent.com` OIDC provider from any other repo using GitHub Actions -- AWS allows only one per URL per account, and creating a duplicate fails. Set it to `true` only on an account with no existing GitHub OIDC provider at all.
- `enable_reports_bucket` (default `true`) creates the S3 bucket. It's **private** -- `aws_s3_bucket_public_access_block` blocks any public ACL/policy -- `scripts/publish_reports.py` generates presigned GET URLs instead. A link works for whoever has it without the findings sitting permanently exposed on the open internet; set `S3_URL_EXPIRY_SECONDS` (repo variable, default 7 days) to change how long a link stays valid.
- `reports_retention_days` (default 30) auto-deletes objects from the bucket via a lifecycle rule -- this is real vulnerability data about a real account, it shouldn't accumulate indefinitely just because storing it is cheap.
- `reports_bucket_name` defaults to `<role_name>-reports-<account_id>` if left empty -- S3 bucket names are globally unique across every AWS account, hence the suffix.

## State

Local state (`terraform.tfstate`, gitignored) by default -- this is one small, low-churn resource group. Point `versions.tf` at a real backend if you'd rather not manage state by hand.
