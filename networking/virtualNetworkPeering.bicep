targetScope = 'resourceGroup'

@minLength(1)
param hubNetworkName string

@minLength(1)
param clusterVNetName string

@minLength(79)
param remoteVirtualNetworkId string

resource variables_hubNetworkName_hub_to_variables_clusterVNetName 'Microsoft.Network/virtualNetworks/virtualNetworkPeerings@2020-05-01' = {
  name: '${hubNetworkName}/hub-to-${clusterVNetName}'
  properties: {
    remoteVirtualNetwork: {
      id: remoteVirtualNetworkId
    }
    allowForwardedTraffic: false
    allowGatewayTransit: false
    allowVirtualNetworkAccess: true
    useRemoteGateways: false
  }
}
