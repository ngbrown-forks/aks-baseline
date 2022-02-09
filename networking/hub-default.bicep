targetScope = 'resourceGroup'

/*** PARAMETERS ***/

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
@description('The hub\'s regional affinity. All resources tied to this hub will also be homed in this region. The network team maintains this approved regional list which is a subset of zones with Availability Zone support.')
param location string

@description('Optional. A /24 to contain the regional firewall, management, and gateway subnet. Defaults to 10.200.0.0/24')
@maxLength(18)
@minLength(10)
param hubVirtualNetworkAddressSpace string = '10.200.0.0/24'

@description('Optional. A /26 under the virtual network address space for the regional Azure Firewall. Defaults to 10.200.0.0/26')
@maxLength(18)
@minLength(10)
param hubVirtualNetworkAzureFirewallSubnetAddressSpace string = '10.200.0.0/26'

@description('Optional. A /27 under the virtual network address space for our regional On-Prem Gateway. Defaults to 10.200.0.64/27')
@maxLength(18)
@minLength(10)
param hubVirtualNetworkGatewaySubnetAddressSpace string = '10.200.0.64/27'

@description('Optional. A /27 under the virtual network address space for regional Azure Bastion. Defaults to 10.200.0.96/27')
@maxLength(18)
@minLength(10)
param hubVirtualNetworkBastionSubnetAddressSpace string = '10.200.0.96/27'

var baseFwPipName = 'pip-fw-${location}'
var hubFwPipNames = [
  '${baseFwPipName}-default'
  '${baseFwPipName}-01'
  '${baseFwPipName}-02'
]
var hubFirewallName = 'fw-${location}'
var fwPolicyBaseName = 'fw-policies-base'
var fwPolicyName = 'fw-policies-${location}'
var vnetHubName = 'vnet-${location}-hub'
var nsgBastionSubnetName = 'nsg-${location}-bastion'
var hubLaName = 'la-hub-${location}-${uniqueString(vnetHub.id)}'

resource laHub 'Microsoft.OperationalInsights/workspaces@2021-06-01' = {
  name: hubLaName
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 30
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
  }
}

// NSG around the Azure Bastion Subnet.
resource nsgBastionSubnet 'Microsoft.Network/networkSecurityGroups@2021-05-01' = {
  name: nsgBastionSubnetName
  location: location
  properties: {
    securityRules: [
      {
        name: 'AllowWebExperienceInbound'
        properties: {
          description: 'Allow our users in. Update this to be as restrictive as possible.'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '443'
          sourceAddressPrefix: 'Internet'
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 100
          direction: 'Inbound'
        }
      }
      {
        name: 'AllowControlPlaneInbound'
        properties: {
          description: 'Service Requirement. Allow control plane access. Regional Tag not yet supported.'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '443'
          sourceAddressPrefix: 'GatewayManager'
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 110
          direction: 'Inbound'
        }
      }
      {
        name: 'AllowHealthProbesInbound'
        properties: {
          description: 'Service Requirement. Allow Health Probes.'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '443'
          sourceAddressPrefix: 'AzureLoadBalancer'
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 120
          direction: 'Inbound'
        }
      }
      {
        name: 'AllowBastionHostToHostInbound'
        properties: {
          description: 'Service Requirement. Allow Required Host to Host Communication.'
          protocol: '*'
          sourcePortRange: '*'
          destinationPortRanges: [
            '8080'
            '5701'
          ]
          sourceAddressPrefix: 'VirtualNetwork'
          destinationAddressPrefix: 'VirtualNetwork'
          access: 'Allow'
          priority: 130
          direction: 'Inbound'
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
        name: 'AllowSshToVnetOutbound'
        properties: {
          description: 'Allow SSH out to the virtual network'
          protocol: 'Tcp'
          sourcePortRange: '*'
          sourceAddressPrefix: '*'
          destinationPortRange: '22'
          destinationAddressPrefix: 'VirtualNetwork'
          access: 'Allow'
          priority: 100
          direction: 'Outbound'
        }
      }
      {
        name: 'AllowRdpToVnetOutbound'
        properties: {
          description: 'Allow RDP out to the virtual network'
          protocol: 'Tcp'
          sourcePortRange: '*'
          sourceAddressPrefix: '*'
          destinationPortRange: '3389'
          destinationAddressPrefix: 'VirtualNetwork'
          access: 'Allow'
          priority: 110
          direction: 'Outbound'
        }
      }
      {
        name: 'AllowControlPlaneOutbound'
        properties: {
          description: 'Required for control plane outbound. Regional prefix not yet supported'
          protocol: 'Tcp'
          sourcePortRange: '*'
          sourceAddressPrefix: '*'
          destinationPortRange: '443'
          destinationAddressPrefix: 'AzureCloud'
          access: 'Allow'
          priority: 120
          direction: 'Outbound'
        }
      }
      {
        name: 'AllowBastionHostToHostOutbound'
        properties: {
          description: 'Service Requirement. Allow Required Host to Host Communication.'
          protocol: '*'
          sourcePortRange: '*'
          sourceAddressPrefix: 'VirtualNetwork'
          destinationPortRanges: [
            '8080'
            '5701'
          ]
          destinationAddressPrefix: 'VirtualNetwork'
          access: 'Allow'
          priority: 130
          direction: 'Outbound'
        }
      }
      {
        name: 'AllowBastionCertificateValidationOutbound'
        properties: {
          description: 'Service Requirement. Allow Required Session and Certificate Validation.'
          protocol: '*'
          sourcePortRange: '*'
          sourceAddressPrefix: '*'
          destinationPortRange: '80'
          destinationAddressPrefix: 'Internet'
          access: 'Allow'
          priority: 140
          direction: 'Outbound'
        }
      }
      {
        name: 'DenyAllOutbound'
        properties: {
          description: 'No further outbound traffic allowed.'
          protocol: '*'
          sourcePortRange: '*'
          destinationPortRange: '*'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
          access: 'Deny'
          priority: 1000
          direction: 'Outbound'
        }
      }
    ]
  }
}

resource bastionNetworkNsgName_Microsoft_Insights_default 'Microsoft.Network/networkSecurityGroups/providers/diagnosticSettings@2017-05-01-preview' = {
  name: '${nsgBastionSubnetName}/Microsoft.Insights/default'
  properties: {
    workspaceId: laHub.id
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
    nsgBastionSubnet
  ]
}

// The regional hub network
resource vnetHub 'Microsoft.Network/virtualNetworks@2021-05-01' = {
  name: vnetHubName
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        hubVirtualNetworkAddressSpace
      ]
    }
    subnets: [
      {
        name: 'AzureFirewallSubnet'
        properties: {
          addressPrefix: hubVirtualNetworkAzureFirewallSubnetAddressSpace
        }
      }
      {
        name: 'GatewaySubnet'
        properties: {
          addressPrefix: hubVirtualNetworkGatewaySubnetAddressSpace
        }
      }
      {
        name: 'AzureBastionSubnet'
        properties: {
          addressPrefix: hubVirtualNetworkBastionSubnetAddressSpace
          networkSecurityGroup: {
            id: nsgBastionSubnet.id
          }
        }
      }
    ]
  }
}

resource vnetHub_diagnosticSettings 'Microsoft.Network/virtualNetworks/providers/diagnosticSettings@2017-05-01-preview' = {
  name: '${vnetHubName}/Microsoft.Insights/default'
  properties: {
    workspaceId: laHub.id
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
      }
    ]
  }
  dependsOn: [
    vnetHub
  ]
}

resource pipsAzureFirewall 'Microsoft.Network/publicIPAddresses@2021-05-01' = [for item in hubFwPipNames: {
  name: item
  location: location
  sku: {
    name: 'Standard'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
    idleTimeoutInMinutes: 4
    publicIPAddressVersion: 'IPv4'
  }
}]

// Azure Firewall starter policy
resource fwPolicyBase 'Microsoft.Network/firewallPolicies@2021-05-01' = {
  name: fwPolicyBaseName
  location: location
  properties: {
    sku: {
      tier: 'Standard'
    }
    threatIntelMode: 'Deny'
    threatIntelWhitelist: {
      ipAddresses: []
    }
    dnsSettings: {
      servers: []
      enableProxy: true
    }
  }
}

// Network hub starts out with only supporting DNS. This is only being done for
// simplicity in this deployment and is not guidance, please ensure all firewall
// rules are aligned with your security standards.
resource defaultNetworkRuleCollectionGroup 'Microsoft.Network/firewallPolicies/ruleCollectionGroups@2021-02-01' = {
  parent: fwPolicyBase
  name: 'DefaultNetworkRuleCollectionGroup'
  location: location
  properties: {
    priority: 200
    ruleCollections: [
      {
        ruleCollectionType: 'FirewallPolicyFilterRuleCollection'
        action: {
          type: 'Allow'
        }
        rules: [
          {
            ruleType: 'NetworkRule'
            name: 'DNS'
            ipProtocols: [
              'UDP'
            ]
            sourceAddresses: [
              '*'
            ]
            sourceIpGroups: []
            destinationAddresses: [
              '*'
            ]
            destinationIpGroups: []
            destinationFqdns: []
            destinationPorts: [
              '53'
            ]
          }
        ]
        name: 'org-wide-allowed'
        priority: 100
      }
    ]
  }
}

resource fwPolicy 'Microsoft.Network/firewallPolicies@2021-02-01' = {
  name: fwPolicyName
  location: location
  properties: {
    basePolicy: {
      id: fwPolicyBase.id
    }
    sku: {
      tier: 'Standard'
    }
    threatIntelMode: 'Deny'
    threatIntelWhitelist: {
      ipAddresses: []
    }
    dnsSettings: {
      servers: []
      enableProxy: true
    }
  }
  dependsOn: [
    defaultNetworkRuleCollectionGroup
  ]
}

resource defaultDnatRuleCollectionGroup 'Microsoft.Network/firewallPolicies/ruleCollectionGroups@2021-02-01' = {
  parent: fwPolicy
  name: 'DefaultDnatRuleCollectionGroup'
  location: location
  properties: {
    priority: 100
    ruleCollections: []
  }
}

resource defaultApplicationRuleCollectionGroup 'Microsoft.Network/firewallPolicies/ruleCollectionGroups@2021-02-01' = {
  parent: fwPolicy
  name: 'DefaultApplicationRuleCollectionGroup'
  location: location
  properties: {
    priority: 300
    ruleCollections: []
  }
  dependsOn: [
    defaultDnatRuleCollectionGroup
  ]
}

resource fwPoliciesName_DefaultNetworkRuleCollectionGroup 'Microsoft.Network/firewallPolicies/ruleCollectionGroups@2021-02-01' = {
  parent: fwPolicy
  name: 'DefaultNetworkRuleCollectionGroup'
  location: location
  properties: {
    priority: 200
    ruleCollections: []
  }
  dependsOn: [
    defaultApplicationRuleCollectionGroup
  ]
}

// This is the regional Azure Firewall that all regional spoke networks can egress through.
resource hubFirewall 'Microsoft.Network/azureFirewalls@2021-05-01' = {
  name: hubFirewallName
  location: location
  zones: [
    '1'
    '2'
    '3'
  ]
  properties: {
    additionalProperties: {}
    sku: {
      name: 'AZFW_VNet'
      tier: 'Standard'
    }
    threatIntelMode: 'Deny'
    ipConfigurations: [
      {
        name: hubFwPipNames[0]
        properties: {
          subnet: {
            id: resourceId('Microsoft.Network/virtualNetworks/subnets', vnetHubName, 'AzureFirewallSubnet')
          }
          publicIPAddress: {
            id: resourceId('Microsoft.Network/publicIpAddresses', hubFwPipNames[0])
          }
        }
      }
      {
        name: hubFwPipNames[1]
        properties: {
          publicIPAddress: {
            id: resourceId('Microsoft.Network/publicIpAddresses', hubFwPipNames[1])
          }
        }
      }
      {
        name: hubFwPipNames[2]
        properties: {
          publicIPAddress: {
            id: resourceId('Microsoft.Network/publicIpAddresses', hubFwPipNames[2])
          }
        }
      }
    ]
    natRuleCollections: []
    networkRuleCollections: []
    applicationRuleCollections: []
    firewallPolicy: {
      id: fwPolicy.id
    }
  }
  dependsOn: [
    pipsAzureFirewall
    vnetHub
    fwPoliciesName_DefaultNetworkRuleCollectionGroup
  ]
}

resource hubFirewall_diagnosticSettings 'Microsoft.Network/azureFirewalls/providers/diagnosticSettings@2017-05-01-preview' = {
  name: '${hubFirewallName}/Microsoft.Insights/default'
  properties: {
    workspaceId: laHub.id
    logs: [
      {
        category: 'AzureFirewallApplicationRule'
        enabled: true
      }
      {
        category: 'AzureFirewallNetworkRule'
        enabled: true
      }
      {
        category: 'AzureFirewallDnsProxy'
        enabled: true
      }
    ]
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
      }
    ]
  }
  dependsOn: [
    hubFirewall
  ]
}

/*** OUTPUTS ***/

output hubVnetId string = vnetHub.id
