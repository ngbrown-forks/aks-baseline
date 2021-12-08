@description('The regional hub network to which this regional spoke will peer to.')
param hubVnetResourceId string

@description('The spokes\'s regional affinity, must be the same as the hub\'s location. All resources tied to this spoke will also be homed in this region. The network team maintains this approved regional list which is a subset of zones with Availability Zone support.')
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
param location string

var orgAppId = 'BU0001A0008'
var clusterVNetName_var = 'vnet-spoke-${orgAppId}-00'
var routeTableName = 'route-to-${location}-hub-fw'
var hubRgName = split(hubVnetResourceId, '/')[4]
var hubNetworkName = split(hubVnetResourceId, '/')[8]
var hubFwResourceId = resourceId(hubRgName, 'Microsoft.Network/azureFirewalls', 'fw-${location}')
var hubLaWorkspaceName = 'la-hub-${location}-${uniqueString(hubVnetResourceId)}'
var hubLaWorkspaceResourceId = resourceId(hubRgName, 'Microsoft.OperationalInsights/workspaces', hubLaWorkspaceName)
var toHubPeeringName = 'spoke-to-${hubNetworkName}'
var primaryClusterPipName_var = 'pip-${orgAppId}-00'

resource routeTable_resource 'Microsoft.Network/routeTables@2020-05-01' = {
  name: routeTableName
  location: location
  properties: {
    routes: [
      {
        name: 'r-nexthop-to-fw'
        properties: {
          nextHopType: 'VirtualAppliance'
          addressPrefix: '0.0.0.0/0'
          nextHopIpAddress: reference(hubFwResourceId, '2020-05-01').ipConfigurations[0].properties.privateIpAddress
        }
      }
    ]
  }
}

resource nsg_clusterVNet_nodepools 'Microsoft.Network/networkSecurityGroups@2020-05-01' = {
  name: 'nsg-${clusterVNetName_var}-nodepools'
  location: location
  properties: {
    securityRules: []
  }
}

resource nsg_clusterVNet_nodepools_Microsoft_Insights_toHub 'Microsoft.Network/networkSecurityGroups/providers/diagnosticSettings@2017-05-01-preview' = {
  name: 'nsg-${clusterVNetName_var}-nodepools/Microsoft.Insights/toHub'
  properties: {
    workspaceId: hubLaWorkspaceResourceId
    logs: [
      {
        category: 'NetworkSecurityGroupEvent'
        enabled: true
      }
      {
        category: 'NetworkSecurityGroupRuleCounter'
        enabled: true
      }
    ]
  }
  dependsOn: [
    nsg_clusterVNet_nodepools
  ]
}

resource nsg_clusterVNet_aksilbs 'Microsoft.Network/networkSecurityGroups@2020-05-01' = {
  name: 'nsg-${clusterVNetName_var}-aksilbs'
  location: location
  properties: {
    securityRules: []
  }
}

resource nsg_clusterVNet_aksilbs_Microsoft_Insights_toHub 'Microsoft.Network/networkSecurityGroups/providers/diagnosticSettings@2017-05-01-preview' = {
  name: 'nsg-${clusterVNetName_var}-aksilbs/Microsoft.Insights/toHub'
  properties: {
    workspaceId: hubLaWorkspaceResourceId
    logs: [
      {
        category: 'NetworkSecurityGroupEvent'
        enabled: true
      }
      {
        category: 'NetworkSecurityGroupRuleCounter'
        enabled: true
      }
    ]
  }
  dependsOn: [
    nsg_clusterVNet_aksilbs
  ]
}

resource nsg_clusterVNet_appgw 'Microsoft.Network/networkSecurityGroups@2020-05-01' = {
  name: 'nsg-${clusterVNetName_var}-appgw'
  location: location
  properties: {
    securityRules: [
      {
        name: 'Allow443InBound'
        properties: {
          description: 'Allow ALL web traffic into 443. (If you wanted to allow-list specific IPs, this is where you\'d list them.)'
          protocol: 'Tcp'
          sourcePortRange: '*'
          sourceAddressPrefix: 'Internet'
          destinationPortRange: '443'
          destinationAddressPrefix: 'VirtualNetwork'
          access: 'Allow'
          priority: 100
          direction: 'Inbound'
        }
      }
      {
        name: 'AllowControlPlaneInBound'
        properties: {
          description: 'Allow Azure Control Plane in. (https://docs.microsoft.com/azure/application-gateway/configuration-infrastructure#network-security-groups)'
          protocol: '*'
          sourcePortRange: '*'
          sourceAddressPrefix: '*'
          destinationPortRange: '65200-65535'
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 110
          direction: 'Inbound'
        }
      }
      {
        name: 'AllowHealthProbesInBound'
        properties: {
          description: 'Allow Azure Health Probes in. (https://docs.microsoft.com/azure/application-gateway/configuration-infrastructure#network-security-groups)'
          protocol: '*'
          sourcePortRange: '*'
          sourceAddressPrefix: 'AzureLoadBalancer'
          destinationPortRange: '*'
          destinationAddressPrefix: 'VirtualNetwork'
          access: 'Allow'
          priority: 120
          direction: 'Inbound'
        }
      }
      {
        name: 'DenyAllInBound'
        properties: {
          protocol: '*'
          sourcePortRange: '*'
          sourceAddressPrefix: '*'
          destinationPortRange: '*'
          destinationAddressPrefix: '*'
          access: 'Deny'
          priority: 1000
          direction: 'Inbound'
        }
      }
      {
        name: 'AllowAllOutBound'
        properties: {
          protocol: '*'
          sourcePortRange: '*'
          sourceAddressPrefix: '*'
          destinationPortRange: '*'
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 1000
          direction: 'Outbound'
        }
      }
    ]
  }
}

resource nsg_clusterVNet_appgw_Microsoft_Insights_toHub 'Microsoft.Network/networkSecurityGroups/providers/diagnosticSettings@2017-05-01-preview' = {
  name: 'nsg-${clusterVNetName_var}-appgw/Microsoft.Insights/toHub'
  properties: {
    workspaceId: hubLaWorkspaceResourceId
    logs: [
      {
        category: 'NetworkSecurityGroupEvent'
        enabled: true
      }
      {
        category: 'NetworkSecurityGroupRuleCounter'
        enabled: true
      }
    ]
  }
  dependsOn: [
    nsg_clusterVNet_appgw
  ]
}

resource clusterVNet_resource 'Microsoft.Network/virtualNetworks@2020-05-01' = {
  name: clusterVNetName_var
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.240.0.0/16'
      ]
    }
    subnets: [
      {
        name: 'snet-clusternodes'
        properties: {
          addressPrefix: '10.240.0.0/22'
          routeTable: {
            id: routeTable_resource.id
          }
          networkSecurityGroup: {
            id: nsg_clusterVNet_nodepools.id
          }
          privateEndpointNetworkPolicies: 'Disabled'
          privateLinkServiceNetworkPolicies: 'Enabled'
        }
      }
      {
        name: 'snet-clusteringressservices'
        properties: {
          addressPrefix: '10.240.4.0/28'
          routeTable: {
            id: routeTable_resource.id
          }
          networkSecurityGroup: {
            id: nsg_clusterVNet_aksilbs.id
          }
          privateEndpointNetworkPolicies: 'Disabled'
          privateLinkServiceNetworkPolicies: 'Disabled'
        }
      }
      {
        name: 'snet-applicationgateway'
        properties: {
          addressPrefix: '10.240.4.16/28'
          networkSecurityGroup: {
            id: nsg_clusterVNet_appgw.id
          }
          privateEndpointNetworkPolicies: 'Disabled'
          privateLinkServiceNetworkPolicies: 'Disabled'
        }
      }
    ]
  }
  resource snetClusternodes 'subnets' existing = {
    name: 'snet-clusternodes'
  }
  resource snetClusterIngressServices 'subnets' existing = {
    name: 'snet-clusteringressservices'
  }
  resource snetAppgw 'subnets' existing = {
    name: 'snet-applicationgateway'
  }
}

resource clusterVNetName_toHubPeering_resource 'Microsoft.Network/virtualNetworks/virtualNetworkPeerings@2020-05-01' = {
  parent: clusterVNet_resource
  name: '${toHubPeeringName}'
  properties: {
    remoteVirtualNetwork: {
      id: hubVnetResourceId
    }
    allowForwardedTraffic: false
    allowVirtualNetworkAccess: true
    allowGatewayTransit: false
    useRemoteGateways: false
  }
}

resource clusterVNet_Microsoft_Insights_toHub 'Microsoft.Network/virtualNetworks/providers/diagnosticSettings@2017-05-01-preview' = {
  name: '${clusterVNetName_var}/Microsoft.Insights/toHub'
  properties: {
    workspaceId: hubLaWorkspaceResourceId
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
      }
    ]
  }
  dependsOn: [
    clusterVNet_resource
  ]
}

module CreateHubTo_clusterVNet_Peer './nested_CreateHubTo_clusterVNetName_Peer.bicep' = {
  name: 'CreateHubTo${clusterVNetName_var}Peer'
  scope: resourceGroup(hubRgName)
  params: {
    resourceId_Microsoft_Network_virtualNetworks_variables_clusterVNetName: clusterVNet_resource.id
    variables_hubNetworkName: hubNetworkName
    variables_clusterVNetName: clusterVNetName_var
  }
  dependsOn: [
    clusterVNetName_toHubPeering_resource
  ]
}

resource primaryClusterPip_resource 'Microsoft.Network/publicIpAddresses@2020-05-01' = {
  name: primaryClusterPipName_var
  location: location
  sku: {
    name: 'Standard'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
    idleTimeoutInMinutes: 4
    publicIPAddressVersion: 'IPv4'
  }
}

output clusterVnetResourceId string = clusterVNet_resource.id
output nodepoolSubnetResourceIds array = [
  clusterVNet_resource::snetClusternodes.id
]
output appGwPublicIpAddress string = primaryClusterPip_resource.properties.ipAddress
