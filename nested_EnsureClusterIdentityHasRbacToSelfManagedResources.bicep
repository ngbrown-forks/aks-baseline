param clusterControlPlaneIdentityPrincipalId string
param vnetNodePoolSubnetResourceId string
param networkContributorRole string
param clusterControlPlaneIdentityName string
param vnetName string
param vnetIngressServicesSubnetResourceId string

resource vnet_resource 'Microsoft.Network/virtualNetworks@2020-05-01' existing = {
  name: vnetName
  resource snet_clusternodes 'subnets' existing = {
    name: 'snet-clusternodes'
  }
  resource snet_clusteringressservices 'subnets' existing = {
    name: 'snet-clusteringressservices'
  }
}

resource clusterRoleAssignmentsToSnetClusternodes 'Microsoft.Authorization/roleAssignments@2020-04-01-preview' = {
  scope: vnet_resource::snet_clusternodes
  name: guid(vnetNodePoolSubnetResourceId, networkContributorRole, clusterControlPlaneIdentityName)
  properties: {
    roleDefinitionId: networkContributorRole
    description: 'Allows cluster identity to join the nodepool vmss resources to this subnet.'
    principalId: clusterControlPlaneIdentityPrincipalId
  }
}

resource clusterRoleAssignmentsToSnetIngressServices 'Microsoft.Authorization/roleAssignments@2020-04-01-preview' = {
  scope: vnet_resource::snet_clusteringressservices
  name: guid(vnetIngressServicesSubnetResourceId, networkContributorRole, clusterControlPlaneIdentityName)
  properties: {
    roleDefinitionId: networkContributorRole
    description: 'Allows cluster identity to join load balancers (ingress resources) to this subnet.'
    principalId: clusterControlPlaneIdentityPrincipalId
  }
}
