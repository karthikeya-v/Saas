targetScope = 'resourceGroup'

@description('Environment tag: dev or prod')
param environment string = 'dev'

@description('Region for all resources')
param location string = resourceGroup().location

@description('Prefix applied to resource names, e.g. timegrid')
param namePrefix string = 'timegrid'

@description('MySQL admin login')
param mysqlAdminUser string = 'timegrid_admin'

@description('MySQL admin password')
@secure()
param mysqlAdminPassword string

@description('JWT signing secret for the backend')
@secure()
param jwtSecret string

var suffix = uniqueString(resourceGroup().id, environment)
var mysqlName = toLower('${namePrefix}-mysql-${suffix}')
var appPlanName = '${namePrefix}-plan-${environment}'
var appName = '${namePrefix}-api-${environment}-${suffix}'
var grafanaAppName = '${namePrefix}-grafana-${environment}-${suffix}'
var kvName = toLower('${namePrefix}kv${suffix}')
var logAnalyticsName = '${namePrefix}-log-${environment}'
var appInsightsName = '${namePrefix}-ai-${environment}'

resource logs 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: logAnalyticsName
  location: location
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 30
  }
}

resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: appInsightsName
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: logs.id
  }
}

resource mysql 'Microsoft.DBforMySQL/flexibleServers@2023-12-30' = {
  name: mysqlName
  location: location
  sku: {
    name: 'Standard_B1ms'
    tier: 'Burstable'
  }
  properties: {
    version: '8.0.21'
    administratorLogin: mysqlAdminUser
    administratorLoginPassword: mysqlAdminPassword
    storage: {
      storageSizeGB: 20
      autoGrow: 'Enabled'
    }
    backup: {
      backupRetentionDays: 7
      geoRedundantBackup: 'Disabled'
    }
    network: {
      publicNetworkAccess: 'Enabled'
    }
    highAvailability: {
      mode: 'Disabled'
    }
  }
}

resource mysqlDb 'Microsoft.DBforMySQL/flexibleServers/databases@2023-12-30' = {
  parent: mysql
  name: 'timegrid'
  properties: {
    charset: 'utf8mb4'
    collation: 'utf8mb4_0900_ai_ci'
  }
}

resource mysqlFirewallAzure 'Microsoft.DBforMySQL/flexibleServers/firewallRules@2023-12-30' = {
  parent: mysql
  name: 'AllowAzureServices'
  properties: {
    startIpAddress: '0.0.0.0'
    endIpAddress: '0.0.0.0'
  }
}

resource kv 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: kvName
  location: location
  properties: {
    tenantId: subscription().tenantId
    sku: { family: 'A', name: 'standard' }
    enableRbacAuthorization: true
    enabledForTemplateDeployment: true
  }
}

resource kvJwt 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: kv
  name: 'jwt-secret'
  properties: { value: jwtSecret }
}

resource kvMysqlPw 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: kv
  name: 'mysql-admin-password'
  properties: { value: mysqlAdminPassword }
}

resource plan 'Microsoft.Web/serverfarms@2023-12-01' = {
  name: appPlanName
  location: location
  sku: {
    name: 'B1'
    tier: 'Basic'
  }
  kind: 'linux'
  properties: { reserved: true }
}

resource api 'Microsoft.Web/sites@2023-12-01' = {
  name: appName
  location: location
  kind: 'app,linux'
  identity: { type: 'SystemAssigned' }
  properties: {
    serverFarmId: plan.id
    siteConfig: {
      linuxFxVersion: 'PYTHON|3.12'
      appCommandLine: 'uvicorn app.main:app --host 0.0.0.0 --port 8000'
      appSettings: [
        { name: 'TG_DB_HOST', value: mysql.properties.fullyQualifiedDomainName }
        { name: 'TG_DB_PORT', value: '3306' }
        { name: 'TG_DB_USER', value: mysqlAdminUser }
        { name: 'TG_DB_PASSWORD', value: mysqlAdminPassword }
        { name: 'TG_DB_NAME', value: 'timegrid' }
        { name: 'TG_JWT_SECRET', value: jwtSecret }
        { name: 'TG_DEV_MODE', value: environment == 'dev' ? 'true' : 'false' }
        { name: 'SCM_DO_BUILD_DURING_DEPLOYMENT', value: 'true' }
        { name: 'APPLICATIONINSIGHTS_CONNECTION_STRING', value: appInsights.properties.ConnectionString }
      ]
    }
    httpsOnly: true
  }
}

resource grafana 'Microsoft.App/containerApps@2024-03-01' existing = if (false) {
  name: grafanaAppName
}

output apiHost string = api.properties.defaultHostName
output mysqlHost string = mysql.properties.fullyQualifiedDomainName
output keyVaultName string = kv.name
output appInsightsConnectionString string = appInsights.properties.ConnectionString
