output "azure_client_id" {
  description = "Set as the AZURE_CLIENT_ID repo variable in GitHub Actions (used by azure/login)."
  value       = azurerm_user_assigned_identity.ci.client_id
}

output "azure_tenant_id" {
  description = "Set as the AZURE_TENANT_ID repo variable in GitHub Actions."
  value       = azurerm_user_assigned_identity.ci.tenant_id
}

output "azure_subscription_id" {
  description = "Set as the AZURE_SUBSCRIPTION_ID repo variable in GitHub Actions."
  value       = var.subscription_id
}

output "reports_storage_account_name" {
  description = "Set as the AZURE_STORAGE_ACCOUNT repo variable to enable link-based report delivery."
  value       = var.enable_reports_storage ? azurerm_storage_account.reports[0].name : null
}

output "reports_container_name" {
  description = "Set as the AZURE_STORAGE_CONTAINER repo variable."
  value       = var.enable_reports_storage ? azurerm_storage_container.reports[0].name : null
}
