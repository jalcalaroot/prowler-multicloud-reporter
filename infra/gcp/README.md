# infra/gcp

GCP equivalent of `infra/aws`/`infra/azure`: creates everything this project needs to run for real against a GCP project, from a handful of parameters. Direct Terraform, no CI/PR pipeline around it -- same one-time-bootstrap reasoning as the other two.

Creates:
- A **Workload Identity Pool + Provider**, so GitHub Actions authenticates via OIDC -- no service account key ever created or downloaded, matching AWS's OIDC-federated IAM role and Azure's federated Managed Identity.
- A **service account** the workflow impersonates through that pool, with **`roles/viewer`** on the project -- Prowler's scan permissions, deliberately not `roles/editor`/`roles/owner`.
- A **private GCS bucket** (never public -- `public_access_prevention = "enforced"`) for publishing reports as time-limited V4 signed links, the GCP-hosted equivalent of `infra/aws`'s S3 bucket / `infra/azure`'s Blob container. Signed without ever holding a downloadable key: the service account is granted `roles/iam.serviceAccountTokenCreator` on *itself*, which lets it sign URLs via the IAM Credentials API's `signBlob` -- the GCP analogue of Azure's user-delegation SAS.

No Vertex AI / any GCP AI service -- the AI summary ([llamafile](https://github.com/Mozilla-Ocho/llamafile)) runs entirely on the GitHub Actions runner, not against any cloud model, same as the other two clouds.

## Usage

```bash
cd infra/gcp
terraform init
terraform apply \
  -var="project_id=<your-project-id>" \
  -var="github_repository=<org>/<repo>"
# add -var="github_repository_id=<numeric id>" to make the trust survive a future repo rename --
# find it with: gh api repos/<org>/<repo> --jq .id
```

Take the outputs and set them as **repo variables** in GitHub (Settings -> Secrets and variables -> Actions -> Variables):

| Output | GitHub variable |
|---|---|
| `workload_identity_provider` | `GCP_WORKLOAD_IDENTITY_PROVIDER` |
| `service_account_email` | `GCP_SERVICE_ACCOUNT_EMAIL` |
| `reports_bucket_name` | `GCS_REPORTS_BUCKET` |

Set `STORAGE_BACKEND=gcs` (repo variable) to route report links through GCS instead of S3/Blob.

## Parameters worth knowing about

- `github_repository_id` (optional, but recommended) matches the Workload Identity Pool provider's trust condition on the repo's **immutable numeric id** instead of its name. Confirmed for real on 2026-09-08 (see the root CLAUDE.md): renaming this GitHub repo broke both AWS's and Azure's name-based OIDC trust and needed a manual Terraform re-apply to fix -- GCP's attribute-condition system can match on `assertion.repository_id` instead of `assertion.repository`, so a future rename here needs no re-apply at all. Find the id with `gh api repos/<org>/<repo> --jq .id`.
- `project_id` should be a **dedicated project**, not a shared one that also hosts unrelated resources -- same reasoning as `infra/azure`'s dedicated resource group. GCP has no equivalent of "one shared subscription with many resource groups" as a first-class concept the way Azure does; a project is the natural isolation boundary.
- `enable_reports_bucket` (default `true`) creates the GCS bucket. It is **private** (`public_access_prevention = "enforced"`, `uniform_bucket_level_access = true`) -- `scripts/publish_reports.py` generates V4 signed URLs via impersonated credentials instead. `reports_retention_days` (default 30) auto-deletes old objects via a lifecycle rule, same reasoning as the other two clouds.
- **Re-applying within 30 days of a teardown?** The Workload Identity Pool (and its provider) soft-delete instead of disappearing -- `terraform apply` will fail with `Error 409: Requested entity already exists` even though it looks gone. Confirmed for real 2026-09-09 (a day after tearing this module down): fix is `gcloud iam workload-identity-pools undelete` + `... providers undelete`, then `terraform import` both back into state before applying again. See the root CLAUDE.md's gotchas for the full command sequence -- this is the GCS bucket's `force_destroy=false` gotcha's sibling, just for the identity pool instead of the storage bucket.
- Signed URLs need the `roles/iam.serviceAccountTokenCreator` self-grant (`google_service_account_iam_member.self_signer`) -- without it, `blob.generate_signed_url()` fails since there's no private key to sign with locally (this identity only ever has short-lived WIF-derived credentials).

## Validated for real (2026-09-08)

Applied for real against the dedicated `prowler-multicloud-reporter` project (8 resources, 0 errors), then the live `multi-cloud-scan` workflow's GCP leg run end to end against it: a real Prowler scan (25 checks, 17 failing), a real llamafile summary, and a real GCS V4 signed URL confirmed fetchable (`HTTP 200`). Unlike Azure, Prowler's GCP provider **did** work inside the `prowlercloud/prowler` Docker image the same way AWS's does -- no native-on-runner workaround needed, since `google-auth` resolves Application Default Credentials in pure Python (no CLI shell-out the way Azure's `AzureCliCredential` needed). Two real bugs were found and fixed getting there, both in the root CLAUDE.md's gotchas: the exported WIF credential config file needed `chmod 644` before mounting into the container (same non-root-container-user class of bug as the `reports/` bind mount), and `storage_backend.py`'s GCS download path crashed on the expected "no history yet" 404 (`google-cloud-storage` doesn't create the destination file before raising `NotFound`, unlike `boto3`/the Azure Blob SDK).

## State

Local state (`terraform.tfstate`, gitignored) by default, same as `infra/aws`/`infra/azure`.
