targetScope = 'subscription'

@description('Policy definition name (keep stable if you want to update in place)')
param policyName string = 'dine-storage-set-smart-tier-preserve'

@description('Effect')
param effect string = 'DeployIfNotExists'

@description('API version for Microsoft.Storage/storageAccounts used by the remediation template')
param storageApiVersion string = '2025-06-01'

// Built-in role: Storage Account Contributor
// If you prefer Contributor, replace with b24988ac-6180-42a0-ab88-20f7382dd24c
var storageAccountContributorRoleId = '/providers/Microsoft.Authorization/roleDefinitions/17d1049b-9a84-46fb-8f53-869881c3d3ab'

resource policyDef 'Microsoft.Authorization/policyDefinitions@2021-06-01' = {
  name: policyName
  properties: {
    policyType: 'Custom'
    mode: 'Indexed'
    displayName: 'Set storage account access tier to Smart, preserve key settings'
    description: 'DeployIfNotExists policy that updates eligible storage accounts to accessTier=Smart while preserving a core set of existing settings (no reference(), no deploymentScripts).'
    metadata: {
      category: 'Storage'
      version: '1.0.0'
    }
    parameters: {
      effect: {
        type: 'String'
        allowedValues: [
          'DeployIfNotExists'
          'Disabled'
        ]
        defaultValue: effect
      }
    }
    policyRule: {
      if: {
        allOf: [
          // Target storage accounts
          {
            field: 'type'
            equals: 'Microsoft.Storage/storageAccounts'
          }

          // Conservative eligibility filter (adjust if you need)
          {
            anyOf: [
              { field: 'kind', equals: 'StorageV2' }
              { field: 'kind', equals: 'BlobStorage' }
            ]
          }

          // Avoid premium SKUs
          {
            field: 'Microsoft.Storage/storageAccounts/sku.name'
            notLike: 'Premium*'
          }

          // Only remediate when not already Smart
          {
            field: 'Microsoft.Storage/storageAccounts/accessTier'
            notEquals: 'Smart'
          }
        ]
      }
      then: {
        effect: '[parameters(\'effect\')]'
        details: {
          type: 'Microsoft.Storage/storageAccounts'
          name: '[field(\'name\')]'
          existenceCondition: {
            field: 'Microsoft.Storage/storageAccounts/accessTier'
            equals: 'Smart'
          }
          roleDefinitionIds: [
            storageAccountContributorRoleId
          ]
          deployment: {
            properties: {
              mode: 'incremental'
              template: {
                '$schema': 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'
                contentVersion: '1.0.0.0'
                parameters: {
                  storageAccountName: { type: 'string' }
                  location: { type: 'string' }
                  kind: { type: 'string' }
                  skuName: { type: 'string' }
                  tags: { type: 'object' }

                  // Core preservation set (common deny / security controls)
                  allowSharedKeyAccess: { type: 'bool' }
                  publicNetworkAccess: { type: 'string' }
                  allowBlobPublicAccess: { type: 'bool' }
                  supportsHttpsTrafficOnly: { type: 'bool' }
                  minimumTlsVersion: { type: 'string' }
                  networkAcls: { type: 'object' }
                  encryption: { type: 'object' }
                }
                resources: [
                  {
                    type: 'Microsoft.Storage/storageAccounts'
                    apiVersion: storageApiVersion
                    name: '[parameters(\'storageAccountName\')]'
                    location: '[parameters(\'location\')]'
                    kind: '[parameters(\'kind\')]'
                    sku: {
                      name: '[parameters(\'skuName\')]'
                    }
                    tags: '[parameters(\'tags\')]'
                    properties: {
                      // The only intended change
                      accessTier: 'Smart'

                      // Preserve core settings by re-applying their current values
                      allowSharedKeyAccess: '[parameters(\'allowSharedKeyAccess\')]'
                      publicNetworkAccess: '[parameters(\'publicNetworkAccess\')]'
                      allowBlobPublicAccess: '[parameters(\'allowBlobPublicAccess\')]'
                      supportsHttpsTrafficOnly: '[parameters(\'supportsHttpsTrafficOnly\')]'
                      minimumTlsVersion: '[parameters(\'minimumTlsVersion\')]'
                      networkAcls: '[parameters(\'networkAcls\')]'
                      encryption: '[parameters(\'encryption\')]'
                    }
                  }
                ]
              }
              parameters: {
                storageAccountName: { value: '[field(\'name\')]' }
                location: { value: '[field(\'location\')]' }
                kind: { value: '[field(\'kind\')]' }
                skuName: { value: '[field(\'Microsoft.Storage/storageAccounts/sku.name\')]' }
                tags: { value: '[field(\'tags\')]' }

                allowSharedKeyAccess: { value: '[field(\'Microsoft.Storage/storageAccounts/allowSharedKeyAccess\')]' }
                publicNetworkAccess: { value: '[field(\'Microsoft.Storage/storageAccounts/publicNetworkAccess\')]' }
                allowBlobPublicAccess: { value: '[field(\'Microsoft.Storage/storageAccounts/allowBlobPublicAccess\')]' }
                supportsHttpsTrafficOnly: { value: '[field(\'Microsoft.Storage/storageAccounts/supportsHttpsTrafficOnly\')]' }
                minimumTlsVersion: { value: '[field(\'Microsoft.Storage/storageAccounts/minimumTlsVersion\')]' }
                networkAcls: { value: '[field(\'Microsoft.Storage/storageAccounts/networkAcls\')]' }
                encryption: { value: '[field(\'Microsoft.Storage/storageAccounts/encryption\')]' }
              }
            }
          }
        }
      }
    }
  }
}
