@description('The regional network spoke VNet Resource ID that the cluster will be joined to')
@minLength(79)
param targetVnetResourceId string

@description('Azure AD Group in the identified tenant that will be granted the highly privileged cluster-admin role. If Azure RBAC is used, then this group will get a role assignment to Azure RBAC, else it will be assigned directly to the cluster\'s admin group.')
param clusterAdminAadGroupObjectId string

@description('Azure AD Group in the identified tenant that will be granted the read only privileges in the a0008 namespace that exists in the cluster. This is only used when Azure RBAC is used for Kubernetes RBAC.')
param a0008NamespaceReaderAadGroupObjectId string

@description('Your AKS control plane Cluster API authentication tenant')
param k8sControlPlaneAuthorizationTenantId string

@description('The certificate data for app gateway TLS termination. It is base64')
param appGatewayListenerCertificate string

@description('The Base64 encoded AKS Ingress Controller public certificate (as .crt or .cer) to be stored in Azure Key Vault as secret and referenced by Azure Application Gateway as a trusted root certificate.')
param aksIngressControllerCertificate string

@description('IP ranges authorized to contact the Kubernetes API server. Passing an empty array will result in no IP restrictions. If any are provided, remember to also provide the public IP of the egress Azure Firewall otherwise your nodes will not be able to talk to the API server (e.g. Flux).')
param clusterAuthorizedIPRanges array = []

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
param kubernetesVersion string = '1.22.2'

@description('Domain name to use for App Gateway and AKS ingress.')
param domainName string = 'contoso.com'

@description('Your cluster will be bootstrapped from this git repo.')
@minLength(9)
param gitOpsBootstrappingRepoHttpsUrl string = 'https://github.com/mspnp/aks-secure-baseline'

@description('You cluster will be bootstrapped from this branch in the identifed git repo.')
@minLength(1)
param gitOpsBootstrappingRepoBranch string = 'main'

var networkContributorRole = '${subscription().id}/providers/Microsoft.Authorization/roleDefinitions/4d97b98b-1d4f-4787-a291-c67834d212e7'
var monitoringMetricsPublisherRole = '${subscription().id}/providers/Microsoft.Authorization/roleDefinitions/3913510d-42f4-4e42-8a64-420c390055eb'
var acrPullRole = '${subscription().id}/providers/Microsoft.Authorization/roleDefinitions/7f951dda-4ed3-4680-a7ca-43fe172d538d'
var managedIdentityOperatorRole = '${subscription().id}/providers/Microsoft.Authorization/roleDefinitions/f1a07417-d97a-45cb-824c-7a7467783830'
var virtualMachineContributorRole = '${subscription().id}/providers/Microsoft.Authorization/roleDefinitions/9980e02c-c2be-4d73-94e8-173b1dc7cf3c'
var keyVaultReader = '${subscription().id}/providers/Microsoft.Authorization/roleDefinitions/21090545-7ca7-4776-b22c-e363652d74d2'
var keyVaultSecretsUserRole = '${subscription().id}/providers/Microsoft.Authorization/roleDefinitions/4633458b-17de-408a-b874-0445c86b69e6'
var clusterAdminRoleId = 'b1ff04bb-8a4e-4dc4-8eb5-8693973ce19b'
var clusterReaderRoleId = '7f6c6a51-bcf8-42ba-9220-52d62157d7db'
var serviceClusterUserRoleId = '4abbcc35-e782-43d8-92c5-2d3f1bd2253f'
var subRgUniqueString = uniqueString('aks', subscription().subscriptionId, resourceGroup().id)
var nodeResourceGroupName = 'rg-${clusterName}-nodepools'
var clusterName = 'aks-${subRgUniqueString}'
var logAnalyticsWorkspaceName = 'la-${clusterName}'
var containerInsightsSolutionName = 'ContainerInsights(${logAnalyticsWorkspaceName})'
var defaultAcrName = 'acraks${subRgUniqueString}'
var vNetResourceGroup = split(targetVnetResourceId, '/')[4]
var vnetName = split(targetVnetResourceId, '/')[8]
var vnetNodePoolSubnetResourceId = '${targetVnetResourceId}/subnets/snet-clusternodes'
var vnetIngressServicesSubnetResourceId = '${targetVnetResourceId}/subnets/snet-cluster-ingressservices'
var agwName = 'apw-${clusterName}'
var akvPrivateDnsZonesName = 'privatelink.vaultcore.azure.net'
var clusterControlPlaneIdentityName = 'mi-${clusterName}-controlplane'
var keyVaultName = 'kv-${clusterName}'
var aksIngressDomainName = 'aks-ingress.${domainName}'
var ingressName = 'bu0001a0008-00'
var aksBackendDomainName = '${ingressName}.${aksIngressDomainName}'
var policyResourceIdAKSLinuxRestrictive = '/providers/Microsoft.Authorization/policySetDefinitions/42b8ef37-b724-4e24-bbc8-7a7708edfe00'
var policyResourceIdEnforceHttpsIngress = '/providers/Microsoft.Authorization/policyDefinitions/1a5b4dca-0b6f-4cf5-907c-56316bc1bf3d'
var policyResourceIdEnforceInternalLoadBalancers = '/providers/Microsoft.Authorization/policyDefinitions/3fc4dc25-5baf-40d8-9b05-7fe74c1bc64e'
var policyResourceIdRoRootFilesystem = '/providers/Microsoft.Authorization/policyDefinitions/df49d893-a74c-421d-bc95-c663042e5b80'
var policyResourceIdEnforceResourceLimits = '/providers/Microsoft.Authorization/policyDefinitions/e345eecc-fa47-480f-9e88-67dcc122b164'
var policyResourceIdEnforceImageSource = '/providers/Microsoft.Authorization/policyDefinitions/febd0533-8e55-448f-b837-bd0e06f16469'
var policyAssignmentNameAKSLinuxRestrictiveName = guid(policyResourceIdAKSLinuxRestrictive, resourceGroup().name, clusterName)
var policyAssignmentNameEnforceHttpsIngressName = guid(policyResourceIdEnforceHttpsIngress, resourceGroup().name, clusterName)
var policyAssignmentNameEnforceInternalLoadBalancersName = guid(policyResourceIdEnforceInternalLoadBalancers, resourceGroup().name, clusterName)
var policyAssignmentNameRoRootFilesystemName = guid(policyResourceIdRoRootFilesystem, resourceGroup().name, clusterName)
var policyAssignmentNameEnforceResourceLimitsName = guid(policyResourceIdEnforceResourceLimits, resourceGroup().name, clusterName)
var policyAssignmentNameEnforceImageSourceName = guid(policyResourceIdEnforceImageSource, resourceGroup().name, clusterName)
var isUsingAzureRBACasKubernetesRBAC = (subscription().tenantId == k8sControlPlaneAuthorizationTenantId)

resource mi_cluster_controlPlane 'Microsoft.ManagedIdentity/userAssignedIdentities@2018-11-30' = {
  name: clusterControlPlaneIdentityName
  location: location
}

resource mi_appgateway_frontend 'Microsoft.ManagedIdentity/userAssignedIdentities@2018-11-30' = {
  name: 'mi-appgateway-frontend'
  location: location
}

resource podmi_ingress_controller 'Microsoft.ManagedIdentity/userAssignedIdentities@2018-11-30' = {
  name: 'podmi-ingress-controller'
  location: location
}

resource keyVault_resource 'Microsoft.KeyVault/vaults@2021-06-01-preview' = {
  name: keyVaultName
  location: location
  properties: {
    accessPolicies: []
    sku: {
      family: 'A'
      name: 'standard'
    }
    tenantId: subscription().tenantId
    networkAcls: {
      bypass: 'AzureServices'
      defaultAction: 'Deny'
      ipRules: []
      virtualNetworkRules: []
    }
    enableRbacAuthorization: true
    enabledForDeployment: false
    enabledForDiskEncryption: false
    enabledForTemplateDeployment: false
    enableSoftDelete: true
  }
  dependsOn: [
    mi_appgateway_frontend
    podmi_ingress_controller
  ]
}

resource keyVaultName_gateway_public_cert 'Microsoft.KeyVault/vaults/secrets@2021-06-01-preview' = {
  parent: keyVault_resource
  name: 'gateway-public-cert'
  properties: {
    value: appGatewayListenerCertificate
  }
}

resource keyVaultName_appgw_ingress_internal_aks_ingress_tls 'Microsoft.KeyVault/vaults/secrets@2021-06-01-preview' = {
  parent: keyVault_resource
  name: 'appgw-ingress-internal-aks-ingress-tls'
  properties: {
    value: aksIngressControllerCertificate
  }
}

resource keyVaultName_Microsoft_Insights_default 'Microsoft.KeyVault/vaults/providers/diagnosticSettings@2017-05-01-preview' = {
  name: '${keyVaultName}/Microsoft.Insights/default'
  properties: {
    workspaceId: resourceId('Microsoft.OperationalInsights/workspaces', logAnalyticsWorkspaceName)
    logs: [
      {
        category: 'AuditEvent'
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
    keyVault_resource
  ]
}

resource keyVaultFrontendSecretsUserRole_resource 'Microsoft.Authorization/roleAssignments@2020-04-01-preview' = {
  name: guid(resourceGroup().id, 'mi-appgateway-frontend', keyVaultSecretsUserRole)
  scope: keyVault_resource
  properties: {
    roleDefinitionId: keyVaultSecretsUserRole
    principalId: mi_appgateway_frontend.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource keyVaultFrontendReader_resource 'Microsoft.Authorization/roleAssignments@2020-04-01-preview' = {
  name: guid(resourceGroup().id, 'mi-appgateway-frontend', keyVaultReader)
  scope: keyVault_resource
  properties: {
    roleDefinitionId: keyVaultReader
    principalId: mi_appgateway_frontend.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource keyVaultIngressSecretsUserRole_resource 'Microsoft.Authorization/roleAssignments@2020-04-01-preview' = {
  name: guid(resourceGroup().id, 'podmi-ingress-controller', keyVaultSecretsUserRole)
  scope: keyVault_resource
  properties: {
    roleDefinitionId: keyVaultSecretsUserRole
    principalId: podmi_ingress_controller.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource keyVaultIngressReader_resource 'Microsoft.Authorization/roleAssignments@2020-04-01-preview' = {
  name: guid(resourceGroup().id, 'podmi-ingress-controller', keyVaultReader)
  scope: keyVault_resource
  properties: {
    roleDefinitionId: keyVaultReader
    principalId: podmi_ingress_controller.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource nodepools_to_akv 'Microsoft.Network/privateEndpoints@2020-05-01' = {
  name: 'nodepools-to-akv'
  location: location
  properties: {
    subnet: {
      id: vnetNodePoolSubnetResourceId
    }
    privateLinkServiceConnections: [
      {
        name: 'nodepools'
        properties: {
          privateLinkServiceId: keyVault_resource.id
          groupIds: [
            'vault'
          ]
        }
      }
    ]
  }
  resource nodepools_to_akv_default 'privateDnsZoneGroups@2020-05-01' = {
    name: 'default'
    properties: {
      privateDnsZoneConfigs: [
        {
          name: 'privatelink-akv-net'
          properties: {
            privateDnsZoneId: akvPrivateDnsZones_resource.id
          }
        }
      ]
    }
  }
}

resource akvPrivateDnsZones_resource 'Microsoft.Network/privateDnsZones@2018-09-01' = {
  name: akvPrivateDnsZonesName
  location: 'global'
  properties: {}
  resource akvPrivateDnsZonesName_to_vnetName 'virtualNetworkLinks@2020-06-01' = {
    name: 'to_${vnetName}'
    location: 'global'
    properties: {
      virtualNetwork: {
        id: targetVnetResourceId
      }
      registrationEnabled: false
    }
  }
}

resource aksIngressDomain_resource 'Microsoft.Network/privateDnsZones@2018-09-01' = {
  name: aksIngressDomainName
  location: 'global'
  properties: {}
  resource aksIngressDomainName_bu0001a0008_00 'A@2018-09-01' = {
    name: ingressName
    properties: {
      ttl: 3600
      aRecords: [
        {
          ipv4Address: '10.240.4.4'
        }
      ]
    }
  }
  resource aksIngressDomainName_to_vnetName 'virtualNetworkLinks@2020-06-01' = {
    name: 'to_${vnetName}'
    location: 'global'
    properties: {
      virtualNetwork: {
        id: targetVnetResourceId
      }
      registrationEnabled: false
    }
  }
}

resource agw_resource 'Microsoft.Network/applicationGateways@2020-05-01' = {
  name: agwName
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${mi_appgateway_frontend.id}': {}
    }
  }
  zones: pickZones('Microsoft.Network', 'applicationGateways', location, 3)
  properties: {
    sku: {
      name: 'WAF_v2'
      tier: 'WAF_v2'
    }
    sslPolicy: {
      policyType: 'Custom'
      cipherSuites: [
        'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384'
        'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'
      ]
      minProtocolVersion: 'TLSv1_2'
    }
    trustedRootCertificates: [
      {
        name: 'root-cert-wildcard-aks-ingress'
        properties: {
          keyVaultSecretId: '${keyVault_resource.properties.vaultUri}secrets/appgw-ingress-internal-aks-ingress-tls'
        }
      }
    ]
    gatewayIPConfigurations: [
      {
        name: 'apw-ip-configuration'
        properties: {
          subnet: {
            id: '${targetVnetResourceId}/subnets/snet-applicationgateway'
          }
        }
      }
    ]
    frontendIPConfigurations: [
      {
        name: 'apw-frontend-ip-configuration'
        properties: {
          publicIPAddress: {
            id: resourceId(subscription().subscriptionId, vNetResourceGroup, 'Microsoft.Network/publicIpAddresses', 'pip-BU0001A0008-00')
          }
        }
      }
    ]
    frontendPorts: [
      {
        name: 'port_443'
        properties: {
          port: 443
        }
      }
    ]
    autoscaleConfiguration: {
      minCapacity: 0
      maxCapacity: 10
    }
    webApplicationFirewallConfiguration: {
      enabled: true
      firewallMode: 'Prevention'
      ruleSetType: 'OWASP'
      ruleSetVersion: '3.2'
      exclusions: []
      fileUploadLimitInMb: 10
      disabledRuleGroups: []
    }
    enableHttp2: false
    sslCertificates: [
      {
        name: '${agwName}-ssl-certificate'
        properties: {
          keyVaultSecretId: '${keyVault_resource.properties.vaultUri}secrets/gateway-public-cert'
        }
      }
    ]
    probes: [
      {
        name: 'probe-${aksBackendDomainName}'
        properties: {
          protocol: 'Https'
          path: '/favicon.ico'
          interval: 30
          timeout: 30
          unhealthyThreshold: 3
          pickHostNameFromBackendHttpSettings: true
          minServers: 0
          match: {}
        }
      }
    ]
    backendAddressPools: [
      {
        name: aksBackendDomainName
        properties: {
          backendAddresses: [
            {
              fqdn: aksBackendDomainName
            }
          ]
        }
      }
    ]
    backendHttpSettingsCollection: [
      {
        name: 'aks-ingress-backendpool-httpsettings'
        properties: {
          port: 443
          protocol: 'Https'
          cookieBasedAffinity: 'Disabled'
          pickHostNameFromBackendAddress: true
          requestTimeout: 20
          probe: {
            id: resourceId('Microsoft.Network/applicationGateways/probes', agwName, 'probe-${aksBackendDomainName}')
          }
          trustedRootCertificates: [
            {
              id: resourceId('Microsoft.Network/applicationGateways/trustedRootCertificates', agwName, 'root-cert-wildcard-aks-ingress')
            }
          ]
        }
      }
    ]
    httpListeners: [
      {
        name: 'listener-https'
        properties: {
          frontendIPConfiguration: {
            id: resourceId('Microsoft.Network/applicationGateways/frontendIPConfigurations', agwName, 'apw-frontend-ip-configuration')
          }
          frontendPort: {
            id: resourceId('Microsoft.Network/applicationGateways/frontendPorts', agwName, 'port_443')
          }
          protocol: 'Https'
          sslCertificate: {
            id: resourceId('Microsoft.Network/applicationGateways/sslCertificates', agwName, '${agwName}-ssl-certificate')
          }
          hostName: 'bicycle.${domainName}'
          hostNames: []
          requireServerNameIndication: true
        }
      }
    ]
    requestRoutingRules: [
      {
        name: 'apw-routing-rules'
        properties: {
          ruleType: 'Basic'
          httpListener: {
            id: resourceId('Microsoft.Network/applicationGateways/httpListeners', agwName, 'listener-https')
          }
          backendAddressPool: {
            id: resourceId('Microsoft.Network/applicationGateways/backendAddressPools', agwName, aksBackendDomainName)
          }
          backendHttpSettings: {
            id: resourceId('Microsoft.Network/applicationGateways/backendHttpSettingsCollection', agwName, 'aks-ingress-backendpool-httpsettings')
          }
        }
      }
    ]
  }
  dependsOn: [
    nodepools_to_akv
    keyVaultFrontendReader_resource
    keyVaultFrontendSecretsUserRole_resource
  ]
}

resource Identifier 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  scope: agw_resource
  name: 'default'
  properties: {
    workspaceId: resourceId('Microsoft.OperationalInsights/workspaces', logAnalyticsWorkspaceName)
    logs: [
      {
        category: 'ApplicationGatewayAccessLog'
        enabled: true
      }
      {
        category: 'ApplicationGatewayPerformanceLog'
        enabled: true
      }
      {
        category: 'ApplicationGatewayFirewallLog'
        enabled: true
      }
    ]
  }
}

module EnsureClusterIdentityHasRbacToSelfManagedResources './nested_EnsureClusterIdentityHasRbacToSelfManagedResources.bicep' = {
  name: 'EnsureClusterIdentityHasRbacToSelfManagedResources'
  scope: resourceGroup(vNetResourceGroup)
  params: {
    clusterControlPlaneIdentityPrincipalId: mi_cluster_controlPlane.properties.principalId
    vnetNodePoolSubnetResourceId: vnetNodePoolSubnetResourceId
    networkContributorRole: networkContributorRole
    clusterControlPlaneIdentityName: mi_cluster_controlPlane.name
    vnetName: vnetName
    vnetIngressServicesSubnetResourceId: vnetIngressServicesSubnetResourceId
  }
}

resource logAnalyticsWorkspaceName_AllPrometheus 'Microsoft.OperationalInsights/workspaces/savedSearches@2020-08-01' = {
  name: '${logAnalyticsWorkspaceName}/AllPrometheus'
  properties: {
    eTag: '*'
    category: 'Prometheus'
    displayName: 'All collected Prometheus information'
    query: 'InsightsMetrics | where Namespace == "prometheus"'
    version: 1
  }
}

resource logAnalyticsWorkspaceName_NodeRebootRequested 'Microsoft.OperationalInsights/workspaces/savedSearches@2020-08-01' = {
  name: '${logAnalyticsWorkspaceName}/NodeRebootRequested'
  properties: {
    eTag: '*'
    category: 'Prometheus'
    displayName: 'Nodes reboot required by kured'
    query: 'InsightsMetrics | where Namespace == "prometheus" and Name == "kured_reboot_required" | where Val > 0'
    version: 1
  }
}

resource PodFailedScheduledQuery 'Microsoft.Insights/scheduledQueryRules@2018-04-16' = {
  name: 'PodFailedScheduledQuery'
  location: location
  properties: {
    description: 'Alert on pod Failed phase.'
    enabled: 'true'
    source: {
      query: '//https://docs.microsoft.com/azure/azure-monitor/insights/container-insights-alerts \r\n let endDateTime = now(); let startDateTime = ago(1h); let trendBinSize = 1m; let clusterName = "${clusterName}"; KubePodInventory | where TimeGenerated < endDateTime | where TimeGenerated >= startDateTime | where ClusterName == clusterName | distinct ClusterName, TimeGenerated | summarize ClusterSnapshotCount = count() by bin(TimeGenerated, trendBinSize), ClusterName | join hint.strategy=broadcast ( KubePodInventory | where TimeGenerated < endDateTime | where TimeGenerated >= startDateTime | distinct ClusterName, Computer, PodUid, TimeGenerated, PodStatus | summarize TotalCount = count(), PendingCount = sumif(1, PodStatus =~ "Pending"), RunningCount = sumif(1, PodStatus =~ "Running"), SucceededCount = sumif(1, PodStatus =~ "Succeeded"), FailedCount = sumif(1, PodStatus =~ "Failed") by ClusterName, bin(TimeGenerated, trendBinSize) ) on ClusterName, TimeGenerated | extend UnknownCount = TotalCount - PendingCount - RunningCount - SucceededCount - FailedCount | project TimeGenerated, TotalCount = todouble(TotalCount) / ClusterSnapshotCount, PendingCount = todouble(PendingCount) / ClusterSnapshotCount, RunningCount = todouble(RunningCount) / ClusterSnapshotCount, SucceededCount = todouble(SucceededCount) / ClusterSnapshotCount, FailedCount = todouble(FailedCount) / ClusterSnapshotCount, UnknownCount = todouble(UnknownCount) / ClusterSnapshotCount| summarize AggregatedValue = avg(FailedCount) by bin(TimeGenerated, trendBinSize)'
      dataSourceId: resourceId('Microsoft.OperationalInsights/workspaces', logAnalyticsWorkspaceName)
      queryType: 'ResultCount'
    }
    schedule: {
      frequencyInMinutes: 5
      timeWindowInMinutes: 10
    }
    action: {
      'odata.type': 'Microsoft.WindowsAzure.Management.Monitoring.Alerts.Models.Microsoft.AppInsights.Nexus.DataContracts.Resources.ScheduledQueryRules.AlertingAction'
      severity: '3'
      trigger: {
        thresholdOperator: 'GreaterThan'
        threshold: 3
        metricTrigger: {
          thresholdOperator: 'GreaterThan'
          threshold: 2
          metricTriggerType: 'Consecutive'
        }
      }
    }
  }
  dependsOn: [
    containerInsightsSolution_resource
  ]
}

resource AllAzureAdvisorAlert 'microsoft.insights/activityLogAlerts@2017-04-01' = {
  name: 'AllAzureAdvisorAlert'
  location: 'Global'
  properties: {
    scopes: [
      resourceGroup().id
    ]
    condition: {
      allOf: [
        {
          field: 'category'
          equals: 'Recommendation'
        }
        {
          field: 'operationName'
          equals: 'Microsoft.Advisor/recommendations/available/action'
        }
      ]
    }
    actions: {
      actionGroups: []
    }
    enabled: true
    description: 'All azure advisor alerts'
  }
}

resource containerInsightsSolution_resource 'Microsoft.OperationsManagement/solutions@2015-11-01-preview' = {
  name: containerInsightsSolutionName
  location: location
  properties: {
    workspaceResourceId: resourceId('Microsoft.OperationalInsights/workspaces', logAnalyticsWorkspaceName)
  }
  plan: {
    name: containerInsightsSolutionName
    product: 'OMSGallery/ContainerInsights'
    promotionCode: ''
    publisher: 'Microsoft'
  }
}

resource KeyVaultAnalytics_logAnalyticsWorkspaceName 'Microsoft.OperationsManagement/solutions@2015-11-01-preview' = {
  name: 'KeyVaultAnalytics(${logAnalyticsWorkspaceName})'
  location: location
  properties: {
    workspaceResourceId: resourceId('Microsoft.OperationalInsights/workspaces', logAnalyticsWorkspaceName)
  }
  plan: {
    name: 'KeyVaultAnalytics(${logAnalyticsWorkspaceName})'
    product: 'OMSGallery/KeyVaultAnalytics'
    promotionCode: ''
    publisher: 'Microsoft'
  }
}

resource cluster_resource 'Microsoft.ContainerService/managedClusters@2021-08-01' = {
  name: clusterName
  location: location
  tags: {
    'Business unit': 'BU0001'
    'Application identifier': 'a0008'
  }
  properties: {
    kubernetesVersion: kubernetesVersion
    dnsPrefix: uniqueString(subscription().subscriptionId, resourceGroup().id, clusterName)
    agentPoolProfiles: [
      {
        name: 'npsystem'
        count: 3
        vmSize: 'Standard_DS2_v2'
        osDiskSizeGB: 80
        osDiskType: 'Ephemeral'
        osType: 'Linux'
        minCount: 3
        maxCount: 4
        vnetSubnetID: vnetNodePoolSubnetResourceId
        enableAutoScaling: true
        type: 'VirtualMachineScaleSets'
        mode: 'System'
        scaleSetPriority: 'Regular'
        scaleSetEvictionPolicy: 'Delete'
        orchestratorVersion: kubernetesVersion
        enableNodePublicIP: false
        maxPods: 30
        availabilityZones: [
          '1'
          '2'
          '3'
        ]
        upgradeSettings: {
          maxSurge: '33%'
        }
        nodeTaints: [
          'CriticalAddonsOnly=true:NoSchedule'
        ]
      }
      {
        name: 'npuser01'
        count: 2
        vmSize: 'Standard_DS3_v2'
        osDiskSizeGB: 120
        osDiskType: 'Ephemeral'
        osType: 'Linux'
        minCount: 2
        maxCount: 5
        vnetSubnetID: vnetNodePoolSubnetResourceId
        enableAutoScaling: true
        type: 'VirtualMachineScaleSets'
        mode: 'User'
        scaleSetPriority: 'Regular'
        scaleSetEvictionPolicy: 'Delete'
        orchestratorVersion: kubernetesVersion
        enableNodePublicIP: false
        maxPods: 30
        availabilityZones: [
          '1'
          '2'
          '3'
        ]
        upgradeSettings: {
          maxSurge: '33%'
        }
      }
    ]
    servicePrincipalProfile: {
      clientId: 'msi'
    }
    addonProfiles: {
      httpApplicationRouting: {
        enabled: false
      }
      omsagent: {
        enabled: true
        config: {
          logAnalyticsWorkspaceResourceId: resourceId('Microsoft.OperationalInsights/workspaces', logAnalyticsWorkspaceName)
        }
      }
      aciConnectorLinux: {
        enabled: false
      }
      azurepolicy: {
        enabled: true
        config: {
          version: 'v2'
        }
      }
      azureKeyvaultSecretsProvider: {
        enabled: true
        config: {
          enableSecretRotation: 'false'
        }
      }
    }
    nodeResourceGroup: nodeResourceGroupName
    enableRBAC: true
    enablePodSecurityPolicy: false
    maxAgentPools: 2
    networkProfile: {
      networkPlugin: 'azure'
      networkPolicy: 'azure'
      outboundType: 'userDefinedRouting'
      loadBalancerSku: 'standard'
      loadBalancerProfile: json('null')
      serviceCidr: '172.16.0.0/16'
      dnsServiceIP: '172.16.0.10'
      dockerBridgeCidr: '172.18.0.1/16'
    }
    aadProfile: {
      managed: true
      enableAzureRBAC: isUsingAzureRBACasKubernetesRBAC
      adminGroupObjectIDs: ((!isUsingAzureRBACasKubernetesRBAC) ? array(clusterAdminAadGroupObjectId) : [])
      tenantID: k8sControlPlaneAuthorizationTenantId
    }
    autoScalerProfile: {
      'balance-similar-node-groups': 'false'
      expander: 'random'
      'max-empty-bulk-delete': '10'
      'max-graceful-termination-sec': '600'
      'max-node-provision-time': '15m'
      'max-total-unready-percentage': '45'
      'new-pod-scale-up-delay': '0s'
      'ok-total-unready-count': '3'
      'scale-down-delay-after-add': '10m'
      'scale-down-delay-after-delete': '20s'
      'scale-down-delay-after-failure': '3m'
      'scale-down-unneeded-time': '10m'
      'scale-down-unready-time': '20m'
      'scale-down-utilization-threshold': '0.5'
      'scan-interval': '10s'
      'skip-nodes-with-local-storage': 'true'
      'skip-nodes-with-system-pods': 'true'
    }
    apiServerAccessProfile: {
      authorizedIPRanges: clusterAuthorizedIPRanges
      enablePrivateCluster: false
    }
    podIdentityProfile: {
      enabled: false
      userAssignedIdentities: []
      userAssignedIdentityExceptions: []
    }
    disableLocalAccounts: true
  }
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${mi_cluster_controlPlane.id}': {}
    }
  }
  sku: {
    name: 'Basic'
    tier: 'Paid'
  }
  dependsOn: [
    containerInsightsSolution_resource
    EnsureClusterIdentityHasRbacToSelfManagedResources
    //resourceId(vNetResourceGroup, 'Microsoft.Resources/deployments', 'EnsureClusterIdentityHasRbacToSelfManagedResources')

    policyAssignmentNameAKSLinuxRestrictive
    policyAssignmentNameEnforceHttpsIngress
    policyAssignmentNameEnforceImageSource
    policyAssignmentNameEnforceInternalLoadBalancers
    policyAssignmentNameEnforceResourceLimits
    policyAssignmentNameRoRootFilesystem
    nodepools_to_akv
    keyVaultIngressReader_resource
    keyVaultIngressSecretsUserRole_resource
  ]
}

// Ensures that flux add-on (extension) is installed.
resource cluster_configuration_flux 'Microsoft.KubernetesConfiguration/extensions@2021-09-01' = {
  scope: cluster_resource
  name: 'flux'
  properties: {
    extensionType: 'Microsoft.Flux'
    autoUpgradeMinorVersion: true
    releaseTrain: 'Stable'
    scope: {
      cluster: {
        releaseNamespace: 'flux-system'
        configurationSettings: {
          'helm-controller.enabled': 'false'
          'source-controller.enabled': 'true'
          'kustomize-controller.enabled': 'true'
          'notification-controller.enabled': 'false'
          'image-automation-controller.enabled': 'false'
          'image-reflector-controller.enabled': 'false'
        }
        configurationProtectedSettings: {}
      }
    }
  }
}

// Bootstraps your cluster using content from your repo
resource cluster_configuration_bootstrap 'Microsoft.KubernetesConfiguration/bootstrap@2021-11-01-preview' = {
  name: 'fluxConfigurations'
  scope: cluster_resource
  properties: {
    scope: 'Cluster'
    namespace: 'flux-system'
    sourceKind: 'GitRepository'
    gitRepository: {
      url: gitOpsBootstrappingRepoHttpsUrl
      timeoutInSeconds: 180
      syncIntervalInSeconds: 300
      repositoryRef: {
        branch: gitOpsBootstrappingRepoBranch
        tag: null
        semver: null
        commit: null
      }
      sshKnownHosts: ''
      httpsUser: null
      httpsCAFile: null
      localAuthRef: null
    }
    kustomizations: {
      unified: {
        path: './cluster-manifests'
        dependsOn: []
        timeoutInSeconds: 300
        syncIntervalInSeconds: 300
        retryIntervalInSeconds: null
        prune: true
        force: false
      }
    }
  }
  dependsOn: [
    cluster_configuration_flux
    resourceId('Microsoft.ContainerRegistry/registries/providers/roleAssignments', defaultAcrName, 'Microsoft.Authorization', guid(cluster_resource.id, acrPullRole))
  ]
}

resource clusterName_Microsoft_Authorization_Microsoft_ContainerService_managedClusters_clusterName_omsagent_monitoringMetricsPublisherRole 'Microsoft.ContainerService/managedClusters/providers/roleAssignments@2020-04-01-preview' = {
  name: '${clusterName}/Microsoft.Authorization/${guid(cluster_resource.id, 'omsagent', monitoringMetricsPublisherRole)}'
  properties: {
    roleDefinitionId: monitoringMetricsPublisherRole
    principalId: reference(cluster_resource.id, '2020-12-01').addonProfiles.omsagent.identity.objectId
    principalType: 'ServicePrincipal'
  }
}

resource clusterName_Microsoft_Insights_default 'Microsoft.ContainerService/managedClusters/providers/diagnosticSettings@2017-05-01-preview' = {
  name: '${clusterName}/Microsoft.Insights/default'
  properties: {
    workspaceId: resourceId('Microsoft.OperationalInsights/workspaces', logAnalyticsWorkspaceName)
    logs: [
      {
        category: 'cluster-autoscaler'
        enabled: true
      }
      {
        category: 'kube-controller-manager'
        enabled: true
      }
      {
        category: 'kube-audit-admin'
        enabled: true
      }
      {
        category: 'guard'
        enabled: true
      }
    ]
  }
  dependsOn: [
    cluster_resource
  ]
}

module EnsureClusterUserAssignedHasRbacToManageVMSS './nested_EnsureClusterUserAssignedHasRbacToManageVMSS.bicep' = {
  name: 'EnsureClusterUserAssignedHasRbacToManageVMSS'
  scope: resourceGroup(nodeResourceGroupName)
  params: {
    clusterKubletIdentityId: reference(cluster_resource.id, '2021-08-01').identityProfile.kubeletidentity.objectId
    virtualMachineContributorRole: virtualMachineContributorRole
  }
  dependsOn: [
    cluster_resource
  ]
}

resource Microsoft_ContainerService_managedClusters_clusterName_acrPullRole 'Microsoft.Authorization/roleAssignments@2020-04-01-preview' = {
  scope: 'Microsoft.ContainerRegistry/registries${defaultAcrName}'
  name: guid(cluster_resource.id, acrPullRole)
  properties: {
    roleDefinitionId: acrPullRole
    description: 'Allows AKS to pull container images from this ACR instance.'
    principalId: reference(cluster_resource.id, '2020-12-01').identityProfile.kubeletidentity.objectId
    principalType: 'ServicePrincipal'
  }
}

resource Microsoft_EventGrid_systemTopics_clusterName 'Microsoft.EventGrid/systemTopics@2020-10-15-preview' = {
  name: clusterName
  location: location
  properties: {
    source: cluster_resource.id
    topicType: 'Microsoft.ContainerService.ManagedClusters'
  }
}

resource Microsoft_EventGrid_systemTopics_providers_diagnosticSettings_clusterName_Microsoft_Insights_default 'Microsoft.EventGrid/systemTopics/providers/diagnosticSettings@2017-05-01-preview' = {
  name: '${clusterName}/Microsoft.Insights/default'
  properties: {
    workspaceId: resourceId('Microsoft.OperationalInsights/workspaces', logAnalyticsWorkspaceName)
    logs: [
      {
        category: 'DeliveryFailures'
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
    Microsoft_EventGrid_systemTopics_clusterName
  ]
}

resource Node_CPU_utilization_high_for_clusterName_CI_1 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: 'Node CPU utilization high for ${clusterName} CI-1'
  location: 'global'
  properties: {
    actions: []
    criteria: {
      allOf: [
        {
          criterionType: 'StaticThresholdCriterion'
          dimensions: [
            {
              name: 'host'
              operator: 'Include'
              values: [
                '*'
              ]
            }
          ]
          metricName: 'cpuUsagePercentage'
          metricNamespace: 'Insights.Container/nodes'
          name: 'Metric1'
          operator: 'GreaterThan'
          threshold: '80'
          timeAggregation: 'Average'
          skipMetricValidation: true
        }
      ]
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
    }
    description: 'Node CPU utilization across the cluster.'
    enabled: true
    evaluationFrequency: 'PT1M'
    scopes: [
      cluster_resource.id
    ]
    severity: 3
    targetResourceType: 'microsoft.containerservice/managedclusters'
    windowSize: 'PT5M'
  }
  dependsOn: [
    containerInsightsSolution_resource
  ]
}

resource Node_working_set_memory_utilization_high_for_clusterName_CI_2 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: 'Node working set memory utilization high for ${clusterName} CI-2'
  location: 'global'
  properties: {
    actions: []
    criteria: {
      allOf: [
        {
          criterionType: 'StaticThresholdCriterion'
          dimensions: [
            {
              name: 'host'
              operator: 'Include'
              values: [
                '*'
              ]
            }
          ]
          metricName: 'memoryWorkingSetPercentage'
          metricNamespace: 'Insights.Container/nodes'
          name: 'Metric1'
          operator: 'GreaterThan'
          threshold: '80'
          timeAggregation: 'Average'
          skipMetricValidation: true
        }
      ]
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
    }
    description: 'Node working set memory utilization across the cluster.'
    enabled: true
    evaluationFrequency: 'PT1M'
    scopes: [
      cluster_resource.id
    ]
    severity: 3
    targetResourceType: 'microsoft.containerservice/managedclusters'
    windowSize: 'PT5M'
  }
  dependsOn: [
    containerInsightsSolution_resource
  ]
}

resource Jobs_completed_more_than_6_hours_ago_for_clusterName_CI_11 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: 'Jobs completed more than 6 hours ago for ${clusterName} CI-11'
  location: 'global'
  properties: {
    actions: []
    criteria: {
      allOf: [
        {
          criterionType: 'StaticThresholdCriterion'
          dimensions: [
            {
              name: 'controllerName'
              operator: 'Include'
              values: [
                '*'
              ]
            }
            {
              name: 'kubernetes namespace'
              operator: 'Include'
              values: [
                '*'
              ]
            }
          ]
          metricName: 'completedJobsCount'
          metricNamespace: 'Insights.Container/pods'
          name: 'Metric1'
          operator: 'GreaterThan'
          threshold: '0'
          timeAggregation: 'Average'
          skipMetricValidation: true
        }
      ]
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
    }
    description: 'This alert monitors completed jobs (more than 6 hours ago).'
    enabled: true
    evaluationFrequency: 'PT1M'
    scopes: [
      cluster_resource.id
    ]
    severity: 3
    targetResourceType: 'microsoft.containerservice/managedclusters'
    windowSize: 'PT1M'
  }
  dependsOn: [
    containerInsightsSolution_resource
  ]
}

resource Container_CPU_usage_high_for_clusterName_CI_9 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: 'Container CPU usage high for ${clusterName} CI-9'
  location: 'global'
  properties: {
    actions: []
    criteria: {
      allOf: [
        {
          criterionType: 'StaticThresholdCriterion'
          dimensions: [
            {
              name: 'controllerName'
              operator: 'Include'
              values: [
                '*'
              ]
            }
            {
              name: 'kubernetes namespace'
              operator: 'Include'
              values: [
                '*'
              ]
            }
          ]
          metricName: 'cpuExceededPercentage'
          metricNamespace: 'Insights.Container/containers'
          name: 'Metric1'
          operator: 'GreaterThan'
          threshold: '90'
          timeAggregation: 'Average'
          skipMetricValidation: true
        }
      ]
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
    }
    description: 'This alert monitors container CPU utilization.'
    enabled: true
    evaluationFrequency: 'PT1M'
    scopes: [
      cluster_resource.id
    ]
    severity: 3
    targetResourceType: 'microsoft.containerservice/managedclusters'
    windowSize: 'PT5M'
  }
  dependsOn: [
    containerInsightsSolution_resource
  ]
}

resource Container_working_set_memory_usage_high_for_clusterName_CI_10 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: 'Container working set memory usage high for ${clusterName} CI-10'
  location: 'global'
  properties: {
    actions: []
    criteria: {
      allOf: [
        {
          criterionType: 'StaticThresholdCriterion'
          dimensions: [
            {
              name: 'controllerName'
              operator: 'Include'
              values: [
                '*'
              ]
            }
            {
              name: 'kubernetes namespace'
              operator: 'Include'
              values: [
                '*'
              ]
            }
          ]
          metricName: 'memoryWorkingSetExceededPercentage'
          metricNamespace: 'Insights.Container/containers'
          name: 'Metric1'
          operator: 'GreaterThan'
          threshold: '90'
          timeAggregation: 'Average'
          skipMetricValidation: true
        }
      ]
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
    }
    description: 'This alert monitors container working set memory utilization.'
    enabled: true
    evaluationFrequency: 'PT1M'
    scopes: [
      cluster_resource.id
    ]
    severity: 3
    targetResourceType: 'microsoft.containerservice/managedclusters'
    windowSize: 'PT5M'
  }
  dependsOn: [
    containerInsightsSolution_resource
  ]
}

resource Pods_in_failed_state_for_clusterName_CI_4 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: 'Pods in failed state for ${clusterName} CI-4'
  location: 'global'
  properties: {
    actions: []
    criteria: {
      allOf: [
        {
          criterionType: 'StaticThresholdCriterion'
          dimensions: [
            {
              name: 'phase'
              operator: 'Include'
              values: [
                'Failed'
              ]
            }
          ]
          metricName: 'podCount'
          metricNamespace: 'Insights.Container/pods'
          name: 'Metric1'
          operator: 'GreaterThan'
          threshold: '0'
          timeAggregation: 'Average'
          skipMetricValidation: true
        }
      ]
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
    }
    description: 'Pod status monitoring.'
    enabled: true
    evaluationFrequency: 'PT1M'
    scopes: [
      cluster_resource.id
    ]
    severity: 3
    targetResourceType: 'microsoft.containerservice/managedclusters'
    windowSize: 'PT5M'
  }
  dependsOn: [
    containerInsightsSolution_resource
  ]
}

resource Disk_usage_high_for_clusterName_CI_5 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: 'Disk usage high for ${clusterName} CI-5'
  location: 'global'
  properties: {
    actions: []
    criteria: {
      allOf: [
        {
          criterionType: 'StaticThresholdCriterion'
          dimensions: [
            {
              name: 'host'
              operator: 'Include'
              values: [
                '*'
              ]
            }
            {
              name: 'device'
              operator: 'Include'
              values: [
                '*'
              ]
            }
          ]
          metricName: 'DiskUsedPercentage'
          metricNamespace: 'Insights.Container/nodes'
          name: 'Metric1'
          operator: 'GreaterThan'
          threshold: '80'
          timeAggregation: 'Average'
          skipMetricValidation: true
        }
      ]
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
    }
    description: 'This alert monitors disk usage for all nodes and storage devices.'
    enabled: true
    evaluationFrequency: 'PT1M'
    scopes: [
      cluster_resource.id
    ]
    severity: 3
    targetResourceType: 'microsoft.containerservice/managedclusters'
    windowSize: 'PT5M'
  }
  dependsOn: [
    containerInsightsSolution_resource
  ]
}

resource Nodes_in_not_ready_status_for_clusterName_CI_3 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: 'Nodes in not ready status for ${clusterName} CI-3'
  location: 'global'
  properties: {
    actions: []
    criteria: {
      allOf: [
        {
          criterionType: 'StaticThresholdCriterion'
          dimensions: [
            {
              name: 'status'
              operator: 'Include'
              values: [
                'NotReady'
              ]
            }
          ]
          metricName: 'nodesCount'
          metricNamespace: 'Insights.Container/nodes'
          name: 'Metric1'
          operator: 'GreaterThan'
          threshold: '0'
          timeAggregation: 'Average'
          skipMetricValidation: true
        }
      ]
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
    }
    description: 'Node status monitoring.'
    enabled: true
    evaluationFrequency: 'PT1M'
    scopes: [
      cluster_resource.id
    ]
    severity: 3
    targetResourceType: 'microsoft.containerservice/managedclusters'
    windowSize: 'PT5M'
  }
  dependsOn: [
    containerInsightsSolution_resource
  ]
}

resource Containers_getting_OOM_killed_for_clusterName_CI_6 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: 'Containers getting OOM killed for ${clusterName} CI-6'
  location: 'global'
  properties: {
    actions: []
    criteria: {
      allOf: [
        {
          criterionType: 'StaticThresholdCriterion'
          dimensions: [
            {
              name: 'kubernetes namespace'
              operator: 'Include'
              values: [
                '*'
              ]
            }
            {
              name: 'controllerName'
              operator: 'Include'
              values: [
                '*'
              ]
            }
          ]
          metricName: 'oomKilledContainerCount'
          metricNamespace: 'Insights.Container/pods'
          name: 'Metric1'
          operator: 'GreaterThan'
          threshold: '0'
          timeAggregation: 'Average'
          skipMetricValidation: true
        }
      ]
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
    }
    description: 'This alert monitors number of containers killed due to out of memory (OOM) error.'
    enabled: true
    evaluationFrequency: 'PT1M'
    scopes: [
      cluster_resource.id
    ]
    severity: 3
    targetResourceType: 'microsoft.containerservice/managedclusters'
    windowSize: 'PT1M'
  }
  dependsOn: [
    containerInsightsSolution_resource
  ]
}

resource Persistent_volume_usage_high_for_clusterName_CI_18 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: 'Persistent volume usage high for ${clusterName} CI-18'
  location: 'global'
  properties: {
    actions: []
    criteria: {
      allOf: [
        {
          criterionType: 'StaticThresholdCriterion'
          dimensions: [
            {
              name: 'podName'
              operator: 'Include'
              values: [
                '*'
              ]
            }
            {
              name: 'kubernetesNamespace'
              operator: 'Include'
              values: [
                '*'
              ]
            }
          ]
          metricName: 'pvUsageExceededPercentage'
          metricNamespace: 'Insights.Container/persistentvolumes'
          name: 'Metric1'
          operator: 'GreaterThan'
          threshold: '80'
          timeAggregation: 'Average'
          skipMetricValidation: true
        }
      ]
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
    }
    description: 'This alert monitors persistent volume utilization.'
    enabled: false
    evaluationFrequency: 'PT1M'
    scopes: [
      cluster_resource.id
    ]
    severity: 3
    targetResourceType: 'microsoft.containerservice/managedclusters'
    windowSize: 'PT5M'
  }
  dependsOn: [
    containerInsightsSolution_resource
  ]
}

resource Pods_not_in_ready_state_for_clusterName_CI_8 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: 'Pods not in ready state for ${clusterName} CI-8'
  location: 'global'
  properties: {
    actions: []
    criteria: {
      allOf: [
        {
          criterionType: 'StaticThresholdCriterion'
          dimensions: [
            {
              name: 'controllerName'
              operator: 'Include'
              values: [
                '*'
              ]
            }
            {
              name: 'kubernetes namespace'
              operator: 'Include'
              values: [
                '*'
              ]
            }
          ]
          metricName: 'PodReadyPercentage'
          metricNamespace: 'Insights.Container/pods'
          name: 'Metric1'
          operator: 'LessThan'
          threshold: '80'
          timeAggregation: 'Average'
          skipMetricValidation: true
        }
      ]
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
    }
    description: 'This alert monitors for excessive pods not in the ready state.'
    enabled: true
    evaluationFrequency: 'PT1M'
    scopes: [
      cluster_resource.id
    ]
    severity: 3
    targetResourceType: 'microsoft.containerservice/managedclusters'
    windowSize: 'PT5M'
  }
  dependsOn: [
    containerInsightsSolution_resource
  ]
}

resource Restarting_container_count_for_clusterName_CI_7 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: 'Restarting container count for ${clusterName} CI-7'
  location: 'global'
  properties: {
    actions: []
    criteria: {
      allOf: [
        {
          criterionType: 'StaticThresholdCriterion'
          dimensions: [
            {
              name: 'kubernetes namespace'
              operator: 'Include'
              values: [
                '*'
              ]
            }
            {
              name: 'controllerName'
              operator: 'Include'
              values: [
                '*'
              ]
            }
          ]
          metricName: 'restartingContainerCount'
          metricNamespace: 'Insights.Container/pods'
          name: 'Metric1'
          operator: 'GreaterThan'
          threshold: '0'
          timeAggregation: 'Average'
          skipMetricValidation: true
        }
      ]
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
    }
    description: 'This alert monitors number of containers restarting across the cluster.'
    enabled: true
    evaluationFrequency: 'PT1M'
    scopes: [
      cluster_resource.id
    ]
    severity: 3
    targetResourceType: 'Microsoft.ContainerService/managedClusters'
    windowSize: 'PT1M'
  }
  dependsOn: [
    containerInsightsSolution_resource
  ]
}

resource aad_admin_group_Microsoft_ContainerService_managedClusters_clusterName_clusterAdminAadGroupObjectId 'Microsoft.Authorization/roleAssignments@2020-04-01-preview' = if (isUsingAzureRBACasKubernetesRBAC) {
  scope: cluster_resource
  name: guid('aad-admin-group', cluster_resource.id, clusterAdminAadGroupObjectId)
  properties: {
    roleDefinitionId: '/subscriptions/${subscription().subscriptionId}/providers/Microsoft.Authorization/roleDefinitions/${clusterAdminRoleId}'
    description: 'Members of this group are cluster admins of this cluster.'
    principalId: clusterAdminAadGroupObjectId
    principalType: 'Group'
  }
}

resource aad_admin_group_sc_Microsoft_ContainerService_managedClusters_clusterName_clusterAdminAadGroupObjectId 'Microsoft.Authorization/roleAssignments@2020-04-01-preview' = if (isUsingAzureRBACasKubernetesRBAC) {
  scope: cluster_resource
  name: guid('aad-admin-group-sc', cluster_resource.id, clusterAdminAadGroupObjectId)
  properties: {
    roleDefinitionId: '/subscriptions/${subscription().subscriptionId}/providers/Microsoft.Authorization/roleDefinitions/${serviceClusterUserRoleId}'
    description: 'Members of this group are cluster users of this cluster.'
    principalId: clusterAdminAadGroupObjectId
    principalType: 'Group'
  }
}

resource aad_a0008_reader_group_Microsoft_ContainerService_managedClusters_clusterName_a0008NamespaceReaderAadGroupObjectId 'Microsoft.Authorization/roleAssignments@2020-04-01-preview' = if (isUsingAzureRBACasKubernetesRBAC && (a0008NamespaceReaderAadGroupObjectId != clusterAdminAadGroupObjectId)) {
  scope: '/subscriptions/${subscription().subscriptionId}/resourcegroups/${resourceGroup().name}/providers/Microsoft.ContainerService/managedClusters/${clusterName}/namespaces/a0008'
  name: guid('aad-a0008-reader-group', cluster_resource.id, a0008NamespaceReaderAadGroupObjectId)
  properties: {
    roleDefinitionId: '/subscriptions/${subscription().subscriptionId}/providers/Microsoft.Authorization/roleDefinitions/${clusterReaderRoleId}'
    principalId: a0008NamespaceReaderAadGroupObjectId
    description: 'Members of this group are cluster admins of the a0008 namespace in this cluster.'
    principalType: 'Group'
  }
}

resource aad_a0008_reader_group_sc_Microsoft_ContainerService_managedClusters_clusterName_a0008NamespaceReaderAadGroupObjectId 'Microsoft.Authorization/roleAssignments@2020-04-01-preview' = if (isUsingAzureRBACasKubernetesRBAC && (a0008NamespaceReaderAadGroupObjectId != clusterAdminAadGroupObjectId)) {
  scope: cluster_resource
  name: guid('aad-a0008-reader-group-sc', cluster_resource.id, a0008NamespaceReaderAadGroupObjectId)
  properties: {
    roleDefinitionId: '/subscriptions/${subscription().subscriptionId}/providers/Microsoft.Authorization/roleDefinitions/${serviceClusterUserRoleId}'
    principalId: a0008NamespaceReaderAadGroupObjectId
    description: 'Members of this group are cluster users of this cluster.'
    principalType: 'Group'
  }
}

resource podmi_ingress_controller_managedIdentityOperatorRole 'Microsoft.Authorization/roleAssignments@2020-04-01-preview' = {
  name: guid(resourceGroup().id, 'podmi-ingress-controller', managedIdentityOperatorRole)
  scope: podmi_ingress_controller
  properties: {
    roleDefinitionId: managedIdentityOperatorRole
    principalId: reference(cluster_resource.id, '2020-11-01').identityProfile.kubeletidentity.objectId
    principalType: 'ServicePrincipal'
  }
}

resource policyAssignmentNameAKSLinuxRestrictive 'Microsoft.Authorization/policyAssignments@2020-03-01' = {
  name: policyAssignmentNameAKSLinuxRestrictiveName
  properties: {
    displayName: '[${clusterName}] ${reference(policyResourceIdAKSLinuxRestrictive, '2020-09-01').displayName}'
    scope: subscriptionResourceId('Microsoft.Resources/resourceGroups', resourceGroup().name)
    policyDefinitionId: policyResourceIdAKSLinuxRestrictive
    parameters: {
      excludedNamespaces: {
        value: [
          'kube-system'
          'gatekeeper-system'
          'azure-arc'
          'cluster-baseline-settings'
        ]
      }
      effect: {
        value: 'audit'
      }
    }
  }
}

resource policyAssignmentNameEnforceHttpsIngress 'Microsoft.Authorization/policyAssignments@2020-03-01' = {
  name: policyAssignmentNameEnforceHttpsIngressName
  properties: {
    displayName: '[${clusterName}] ${reference(policyResourceIdEnforceHttpsIngress, '2020-09-01').displayName}'
    scope: subscriptionResourceId('Microsoft.Resources/resourceGroups', resourceGroup().name)
    policyDefinitionId: policyResourceIdEnforceHttpsIngress
    parameters: {
      excludedNamespaces: {
        value: []
      }
      effect: {
        value: 'deny'
      }
    }
  }
}

resource policyAssignmentNameEnforceInternalLoadBalancers 'Microsoft.Authorization/policyAssignments@2020-03-01' = {
  name: policyAssignmentNameEnforceInternalLoadBalancersName
  properties: {
    displayName: '[${clusterName}] ${reference(policyResourceIdEnforceInternalLoadBalancers, '2020-09-01').displayName}'
    scope: subscriptionResourceId('Microsoft.Resources/resourceGroups', resourceGroup().name)
    policyDefinitionId: policyResourceIdEnforceInternalLoadBalancers
    parameters: {
      excludedNamespaces: {
        value: []
      }
      effect: {
        value: 'deny'
      }
    }
  }
}

resource policyAssignmentNameRoRootFilesystem 'Microsoft.Authorization/policyAssignments@2020-03-01' = {
  name: policyAssignmentNameRoRootFilesystemName
  properties: {
    displayName: '[${clusterName}] ${reference(policyResourceIdRoRootFilesystem, '2020-09-01').displayName}'
    scope: subscriptionResourceId('Microsoft.Resources/resourceGroups', resourceGroup().name)
    policyDefinitionId: policyResourceIdRoRootFilesystem
    parameters: {
      excludedNamespaces: {
        value: [
          'kube-system'
          'gatekeeper-system'
          'azure-arc'
        ]
      }
      effect: {
        value: 'audit'
      }
    }
  }
}

resource policyAssignmentNameEnforceResourceLimits 'Microsoft.Authorization/policyAssignments@2020-03-01' = {
  name: policyAssignmentNameEnforceResourceLimitsName
  properties: {
    displayName: '[${clusterName}] ${reference(policyResourceIdEnforceResourceLimits, '2020-09-01').displayName}'
    scope: subscriptionResourceId('Microsoft.Resources/resourceGroups', resourceGroup().name)
    policyDefinitionId: policyResourceIdEnforceResourceLimits
    parameters: {
      cpuLimit: {
        value: '1000m'
      }
      memoryLimit: {
        value: '512Mi'
      }
      excludedNamespaces: {
        value: [
          'kube-system'
          'gatekeeper-system'
          'azure-arc'
          'cluster-baseline-settings'
          'flux-system'
        ]
      }
      effect: {
        value: 'deny'
      }
    }
  }
}

resource policyAssignmentNameEnforceImageSource 'Microsoft.Authorization/policyAssignments@2020-03-01' = {
  name: policyAssignmentNameEnforceImageSourceName
  properties: {
    displayName: '[${clusterName}] ${reference(policyResourceIdEnforceImageSource, '2020-09-01').displayName}'
    scope: subscriptionResourceId('Microsoft.Resources/resourceGroups', resourceGroup().name)
    policyDefinitionId: policyResourceIdEnforceImageSource
    parameters: {
      allowedContainerImagesRegex: {
        value: '${defaultAcrName}.azurecr.io/.+$|mcr.microsoft.com/.+$|azurearcfork8s.azurecr.io/azurearcflux/images/stable/.+$|docker.io/fluxcd/flux.+$|docker.io/weaveworks/kured.+$|docker.io/library/.+$'
      }
      excludedNamespaces: {
        value: [
          'kube-system'
          'gatekeeper-system'
          'azure-arc'
        ]
      }
      effect: {
        value: 'deny'
      }
    }
  }
}

output aksClusterName string = clusterName
output aksIngressControllerPodManagedIdentityResourceId string = podmi_ingress_controller.id
output aksIngressControllerPodManagedIdentityClientId string = reference(podmi_ingress_controller.id, '2018-11-30').clientId
output keyVaultName string = keyVaultName
