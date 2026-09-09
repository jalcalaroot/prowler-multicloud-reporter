resource "random_string" "suffix" {
  length  = 8
  upper   = false
  special = false
  numeric = true
}

resource "azurerm_resource_group" "rg" {
  name     = var.resource_group_name
  location = var.location
}

locals {
  storage_account_name = var.storage_account_name != "" ? var.storage_account_name : "${var.base_name}rpt${random_string.suffix.result}"
}

# ---------------------------------------------------------------------------
# GitHub OIDC identity -- User-Assigned Managed Identity + federated
# credential, mirroring infra/aws's IAM role. No client secret, no static
# credential: GitHub's OIDC token is exchanged for an Entra ID token at
# workflow run time.
# ---------------------------------------------------------------------------
resource "azurerm_user_assigned_identity" "ci" {
  name                = "id-prowler-multicloud-agent-ci"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
}

# Azure federated credentials match on an EXACT subject string (no wildcard
# like AWS's StringLike condition) -- this covers workflow_dispatch/push runs
# from main. Add another azurerm_federated_identity_credential block (a
# different `name`, same identity) for other trigger contexts (e.g. a
# specific GitHub Environment) if this workflow ever needs to run from
# somewhere else.
resource "azurerm_federated_identity_credential" "github" {
  name                      = "github-actions-main"
  user_assigned_identity_id = azurerm_user_assigned_identity.ci.id
  audience                  = ["api://AzureADTokenExchange"]
  issuer                    = "https://token.actions.githubusercontent.com"
  subject                   = "${var.github_subject_prefix != "" ? var.github_subject_prefix : "repo:${var.github_repository}"}:ref:refs/heads/main"
}

# Read-only cloud coverage for Prowler -- deliberately not Contributor/Owner.
resource "azurerm_role_assignment" "reader" {
  scope                = "/subscriptions/${var.subscription_id}"
  role_definition_name = "Reader"
  principal_id         = azurerm_user_assigned_identity.ci.principal_id
}

# ---------------------------------------------------------------------------
# Reports storage -- Blob equivalent of infra/aws's private S3 bucket.
# ---------------------------------------------------------------------------
resource "azurerm_storage_account" "reports" {
  count                           = var.enable_reports_storage ? 1 : 0
  name                            = local.storage_account_name
  resource_group_name             = azurerm_resource_group.rg.name
  location                        = azurerm_resource_group.rg.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false # no anonymous public blob/container access, ever
}

resource "azurerm_storage_container" "reports" {
  count              = var.enable_reports_storage ? 1 : 0
  name               = var.reports_container_name
  storage_account_id = azurerm_storage_account.reports[0].id
}

resource "azurerm_storage_management_policy" "reports" {
  count              = var.enable_reports_storage ? 1 : 0
  storage_account_id = azurerm_storage_account.reports[0].id

  rule {
    name    = "expire-old-runs"
    enabled = true
    filters {
      blob_types = ["blockBlob"]
    }
    actions {
      base_blob {
        delete_after_days_since_modification_greater_than = var.reports_retention_days
      }
    }
  }
}

resource "azurerm_role_assignment" "storage_blob_contributor" {
  count                = var.enable_reports_storage ? 1 : 0
  scope                = azurerm_storage_account.reports[0].id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_user_assigned_identity.ci.principal_id
}
