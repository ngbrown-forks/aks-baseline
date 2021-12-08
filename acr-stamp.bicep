@description('The regional network spoke VNet Resource ID that the cluster will be joined to.')
@minLength(79)
param targetVnetResourceId string

@description('AKS Service, Node Pool, and supporting services (KeyVault, App Gateway, etc) region. This needs to be the same region as the vnet provided in these parameters.')
@allowed([
  'australiaeast'
  'canadacentral'
  'centralus'
  'eastus'
  'eastus2'
  'westus2'
  'francecentral'
  'germanywestcentral'
  'northeurope'
  'southafricanorth'
  'southcentralus'
  'uksouth'
  'westeurope'
  'japaneast'
  'southeastasia'
])
param location string = 'eastus2'

@description('For Azure resources that support native geo-redunancy, provide the location the redundant service will have its secondary. Should be different than the location parameter and ideally should be a paired region - https://docs.microsoft.com/azure/best-practices-availability-paired-regions. This region does not need to support availability zones.')
@allowed([
  'australiasoutheast'
  'canadaeast'
  'eastus2'
  'westus'
  'centralus'
  'westcentralus'
  'francesouth'
  'germanynorth'
  'westeurope'
  'ukwest'
  'northeurope'
  'japanwest'
  'southafricawest'
  'northcentralus'
  'eastasia'
  'eastus'
  'westus2'
  'francecentral'
  'uksouth'
  'japaneast'
  'southeastasia'
])
param geoRedundancyLocation string = 'centralus'

var subRgUniqueString = uniqueString('aks', subscription().subscriptionId, resourceGroup().id)
var clusterName = 'aks-${subRgUniqueString}'
var logAnalyticsWorkspaceName_var = 'la-${clusterName}'
var defaultAcrName_var = 'acraks${subRgUniqueString}'
var vnetName = split(targetVnetResourceId, '/')[8]
var vnetAcrPrivateEndpointSubnetResourceId = '${targetVnetResourceId}/subnets/snet-clusternodes'
var acrPrivateDnsZonesName_var = 'privatelink.azurecr.io'

resource logAnalyticsWorkspace_resource 'Microsoft.OperationalInsights/workspaces@2020-10-01' = {
  name: logAnalyticsWorkspaceName_var
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 30
  }
}

resource acrPrivateDnsZones_resource 'Microsoft.Network/privateDnsZones@2020-06-01' = {
  name: acrPrivateDnsZonesName_var
  location: 'global'
  properties: {}
}

resource acrPrivateDnsZones_to_vnetName 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2020-06-01' = {
  parent: acrPrivateDnsZones_resource
  name: 'to_${vnetName}'
  location: 'global'
  properties: {
    virtualNetwork: {
      id: targetVnetResourceId
    }
    registrationEnabled: false
  }
}

resource defaultAcr_resource 'Microsoft.ContainerRegistry/registries@2020-11-01-preview' = {
  name: defaultAcrName_var
  location: location
  sku: {
    name: 'Premium'
  }
  properties: {
    adminUserEnabled: false
    networkRuleSet: {
      defaultAction: 'Deny'
      virtualNetworkRules: []
      ipRules: []
    }
    policies: {
      quarantinePolicy: {
        status: 'disabled'
      }
      trustPolicy: {
        type: 'Notary'
        status: 'disabled'
      }
      retentionPolicy: {
        days: 15
        status: 'enabled'
      }
    }
    publicNetworkAccess: 'Disabled'
    encryption: {
      status: 'disabled'
    }
    dataEndpointEnabled: true
    networkRuleBypassOptions: 'AzureServices'
    zoneRedundancy: 'Disabled'
  }
}

resource defaultAcr_geoRedundancyLocation 'Microsoft.ContainerRegistry/registries/replications@2020-11-01-preview' = {
  parent: defaultAcr_resource
  name: '${geoRedundancyLocation}'
  location: geoRedundancyLocation
  properties: {}
}

resource defaultAcr_Microsoft_Insights_default 'Microsoft.ContainerRegistry/registries/providers/diagnosticSettings@2017-05-01-preview' = {
  name: '${defaultAcrName_var}/Microsoft.Insights/default'
  properties: {
    workspaceId: logAnalyticsWorkspace_resource.id
    metrics: [
      {
        timeGrain: 'PT1M'
        category: 'AllMetrics'
        enabled: true
      }
    ]
    logs: [
      {
        category: 'ContainerRegistryRepositoryEvents'
        enabled: true
      }
      {
        category: 'ContainerRegistryLoginEvents'
        enabled: true
      }
    ]
  }
  dependsOn: [
    defaultAcr_resource
  ]
}

resource acr_to_vnetName 'Microsoft.Network/privateEndpoints@2020-11-01' = {
  name: 'acr_to_${vnetName}'
  location: location
  properties: {
    subnet: {
      id: vnetAcrPrivateEndpointSubnetResourceId
    }
    privateLinkServiceConnections: [
      {
        name: 'nodepools'
        properties: {
          privateLinkServiceId: defaultAcr_resource.id
          groupIds: [
            'registry'
          ]
        }
      }
    ]
  }
  dependsOn: [
    defaultAcr_geoRedundancyLocation
  ]
}

resource acr_to_vnetName_default 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2020-11-01' = {
  parent: acr_to_vnetName
  name: 'default'
  location: location
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'privatelink-azurecr-io'
        properties: {
          privateDnsZoneId: acrPrivateDnsZones_resource.id
        }
      }
    ]
  }
}

output containerRegistryName string = defaultAcrName_var
