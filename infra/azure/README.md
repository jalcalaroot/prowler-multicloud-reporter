# infra/azure

Azure equivalent of `infra/aws`: creates everything this project needs to run for real against an Azure subscription, from a handful of parameters. Direct Terraform, no CI/PR pipeline around it -- same one-time-bootstrap reasoning as `infra/aws`.

Creates:
- A **User-Assigned Managed Identity** + federated credential, so GitHub Actions authenticates via OIDC (no client secret, no static credential).
- **`Reader`** role on the subscription for that identity -- Prowler's scan permissions, deliberately not `Contributor`/`Owner`.
- A **private Blob Storage container** (never public) for publishing reports as time-limited SAS-token links -- the Azure-hosted equivalent of `infra/aws`'s S3 bucket.

No Azure OpenAI / Cognitive Services resources -- the AI summary ([llamafile](https://github.com/Mozilla-Ocho/llamafile)) runs entirely on the GitHub Actions runner, not against any Azure model.

## Usage

```bash
cd infra/azure
terraform init
terraform apply \
  -var="subscription_id=<your-subscription-id>" \
  -var="github_repository=<org>/<repo>"
```

Applied and validated for real against a live subscription multiple times -- most recently as 9 resources, 0 errors -- and the report pipeline run against the result end to end each time, with a real signed Blob URL verified fetchable (`HTTP 200`). Torn down again each time once validated (see the root CLAUDE.md) -- this isn't infrastructure meant to sit running by default.

Take the outputs and set them as **repo variables** in GitHub (Settings -> Secrets and variables -> Actions -> Variables):

| Output | GitHub variable |
|---|---|
| `azure_client_id` | `AZURE_CLIENT_ID` |
| `azure_tenant_id` | `AZURE_TENANT_ID` |
| `azure_subscription_id` | `AZURE_SUBSCRIPTION_ID` |
| `reports_storage_account_name` | `AZURE_STORAGE_ACCOUNT` |
| `reports_container_name` | `AZURE_STORAGE_CONTAINER` |

Set `STORAGE_BACKEND=azure-blob` (repo variable) to route report links through Azure instead of AWS.

## Parameters worth knowing about

- `location` defaults to `eastus` -- confirmed across multiple real applies to avoid the "Allowed locations" governance-policy block that `eastus2` hit on this account (see the root CLAUDE.md's policy-exemption story). Switch it only if your own subscription's governance policy requires a different region.
- The federated credential's `subject` is an **exact string match** (`repo:<org>/<repo>:ref:refs/heads/main`) -- unlike AWS's `StringLike` condition, Azure has no wildcard here. Add another `azurerm_federated_identity_credential` block (different `name`, same identity) if this needs to run from another ref/environment. Some GitHub accounts also customize the OIDC subject format itself (numeric IDs instead of names) -- confirmed for real on this account (`AADSTS700213: No matching federated identity record found`) -- set `github_subject_prefix` the same way `infra/aws/README.md` documents (check `gh api repos/<org>/<repo>/actions/oidc/customization/sub` first). Azure's exact-match subject makes this bite harder than AWS's `StringLike` wildcard: a wrong prefix here fails every single run, not just edge cases.
- `enable_reports_storage` (default `true`) creates the Blob container. It is **private** (`allow_nested_items_to_be_public = false`) -- `scripts/publish_reports.py` generates user-delegation SAS URLs (signed with a short-lived Entra ID key, not the storage account's static access key) instead. `reports_retention_days` (default 30) auto-deletes old blobs via a lifecycle policy, same reasoning as `infra/aws`.

## State

Local state (`terraform.tfstate`, gitignored) by default, same as `infra/aws`.
