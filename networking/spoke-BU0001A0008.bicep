targetScope = 'resourceGroup'

/*** PARAMETERS ***/

@description('The regional hub network to which this regional spoke will peer to.')
@minLength(79)
param hubVnetResourceId string

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
@description('The spokes\'s regional affinity, must be the same as the hub\'s location. All resources tied to this spoke will also be homed in this region. The network team maintains this approved regional list which is a subset of zones with Availability Zone support.')
param location string

// A designator that represents a business unit id and application id
var orgAppId = 'BU0001A0008'
var clusterVNetName = 'vnet-spoke-${orgAppId}-00'
var routeTableName = 'route-to-${location}-hub-fw'
var hubRgName = split(hubVnetResourceId, '/')[4]
var hubNetworkName = split(hubVnetResourceId, '/')[8]
var hubFwResourceId = resourceId(hubRgName, 'Microsoft.Network/azureFirewalls', 'fw-${location}')
var hubLaWorkspaceName = 'la-hub-${location}-${uniqueString(hubVnetResourceId)}'
var hubLaWorkspaceResourceId = resourceId(hubRgName, 'Microsoft.OperationalInsights/workspaces', hubLaWorkspaceName)
var toHubPeeringName = 'spoke-to-${hubNetworkName}'
var primaryClusterPipName_var = 'pip-${orgAppId}-00'


/*** RESOURCES ***/

// Next hop to the regional hub's Azure Firewall
resource routeNextHopToFirewall 'Microsoft.Network/routeTables@2021-05-01' = {
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

// Default NSG on the AKS nodepools. Feel free to constrict further.
resource nsgNodepoolSubnet 'Microsoft.Network/networkSecurityGroups@2021-05-01' = {
  name: 'nsg-${clusterVNetName}-nodepools'
  location: location
  properties: {
    securityRules: []
  }
}

resource nsg_clusterVNet_nodepools_Microsoft_Insights_toHub 'Microsoft.Network/networkSecurityGroups/providers/diagnosticSettings@2017-05-01-preview' = {
  name: 'nsg-${clusterVNetName}-nodepools/Microsoft.Insights/toHub'
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
    nsgNodepoolSubnet
  ]
}

// Default NSG on the AKS internal load balancer subnet. Feel free to constrict further.
resource nsgInternalLoadBalancerSubnet 'Microsoft.Network/networkSecurityGroups@2021-05-01' = {
  name: 'nsg-${clusterVNetName}-aksilbs'
  location: location
  properties: {
    securityRules: []
  }
}

resource nsg_clusterVNet_aksilbs_Microsoft_Insights_toHub 'Microsoft.Network/networkSecurityGroups/providers/diagnosticSettings@2017-05-01-preview' = {
  name: 'nsg-${clusterVNetName}-aksilbs/Microsoft.Insights/toHub'
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
    nsgInternalLoadBalancerSubnet
  ]
}

// NSG on the Application Gateway subnet.
resource nsgAppGwSubnet 'Microsoft.Network/networkSecurityGroups@2021-05-01' = {
  name: 'nsg-${clusterVNetName}-appgw'
  location: location
  properties: {
    securityRules: [
      {
        name: 'Allow443Inbound'
        properties: {
          description: 'Allow ALL web traffic into 443. (If you wanted to allow-list specific IPs, this is where you\'d list them.)'
          protocol: 'Tcp'
          sourcePortRange: '*'
          sourceAddressPrefix: 'Internet'
          destinationPortRange: '443'
          destinationAddressPrefix: 'VirtualNetwork'
          direction: 'Inbound'
          access: 'Allow'
          priority: 100
        }
      }
      {
        name: 'AllowControlPlaneInbound'
        properties: {
          description: 'Allow Azure Control Plane in. (https://docs.microsoft.com/azure/application-gateway/configuration-infrastructure#network-security-groups)'
          protocol: '*'
          sourcePortRange: '*'
          sourceAddressPrefix: '*'
          destinationPortRange: '65200-65535'
          destinationAddressPrefix: '*'
          direction: 'Inbound'
          access: 'Allow'
          priority: 110
        }
      }
      {
        name: 'AllowHealthProbesInbound'
        properties: {
          description: 'Allow Azure Health Probes in. (https://docs.microsoft.com/azure/application-gateway/configuration-infrastructure#network-security-groups)'
          protocol: '*'
          sourcePortRange: '*'
          sourceAddressPrefix: 'AzureLoadBalancer'
          destinationPortRange: '*'
          destinationAddressPrefix: 'VirtualNetwork'
          direction: 'Inbound'
          access: 'Allow'
          priority: 120
        }
      }
      {
        name: 'DenyAllInbound'
        properties: {
          description: 'No further inbound traffic allowed.'
          protocol: '*'
          sourcePortRange: '*'
          destinationPortRange: '*'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
          access: 'Deny'
          priority: 1000
          direction: 'Inbound'
        }
      }
      {
        name: 'AllowAllOutbound'
        properties: {
          description: 'App Gateway v2 requires full outbound access.'
          protocol: '*'
          sourcePortRange: '*'
          destinationPortRange: '*'
          sourceAddressPrefix: '*'
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
  name: 'nsg-${clusterVNetName}-appgw/Microsoft.Insights/toHub'
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
    nsgAppGwSubnet
  ]
}

// The spoke virtual network.
// 65,536 (-reserved) IPs available to the workload, split across two subnets for AKS and one for App Gateway.
resource vnetSpoke 'Microsoft.Network/virtualNetworks@2021-05-01' = {
  name: clusterVNetName
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
            id: routeNextHopToFirewall.id
          }
          networkSecurityGroup: {
            id: nsgNodepoolSubnet.id
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
            id: routeNextHopToFirewall.id
          }
          networkSecurityGroup: {
            id: nsgInternalLoadBalancerSubnet.id
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
            id: nsgAppGwSubnet.id
          }
          privateEndpointNetworkPolicies: 'Disabled'
          privateLinkServiceNetworkPolicies: 'Disabled'
        }
      }
    ]
  }

  resource snetClusterNodes 'subnets' existing = {
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
  parent: vnetSpoke
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
  name: '${clusterVNetName}/Microsoft.Insights/toHub'
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
    vnetSpoke
  ]
}

module CreateHubTo_clusterVNet_Peer './virtualNetworkPeering.bicep' = {
  name: 'CreateHubTo${clusterVNetName}Peer'
  scope: resourceGroup(hubRgName)
  params: {
    remoteVirtualNetworkId: vnetSpoke.id
    hubNetworkName: hubNetworkName
    clusterVNetName: clusterVNetName
  }
  dependsOn: [
    clusterVNetName_toHubPeering_resource
  ]
}

// Used as primary public entry point for cluster. Expected to be assigned to an Azure Application Gateway.
// This is a public facing IP, and would be best behind a DDoS Policy (not deployed simply for cost considerations)
resource pipPrimaryClusterIp 'Microsoft.Network/publicIpAddresses@2020-05-01' = {
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

/*** OUTPUTS ***/

output clusterVnetResourceId string = vnetSpoke.id
output nodepoolSubnetResourceIds array = [
  vnetSpoke::snetClusterNodes.id
]
output appGwPublicIpAddress string = pipPrimaryClusterIp.properties.ipAddress
