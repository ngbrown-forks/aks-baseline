param clusterKubletIdentityId string
param virtualMachineContributorRole string

resource id 'Microsoft.Authorization/roleAssignments@2020-04-01-preview' = {
  name: guid(resourceGroup().id, virtualMachineContributorRole)
  properties: {
    roleDefinitionId: virtualMachineContributorRole
    principalId: clusterKubletIdentityId
  }
}
