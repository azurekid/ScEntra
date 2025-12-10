# Service Principal Setup for ScEntra

<p align="center">
  <img src="../images/ScEntra-background.png" alt="ScEntra" width="400" style="max-width: 100%; height: auto;">
</p>

This guide explains how to create and configure a service principal for running ScEntra in automated environments, CI/CD pipelines, or production scenarios where interactive authentication isn't suitable.

## Prerequisites

**No PowerShell modules required!** The setup uses direct Microsoft Graph REST API calls.

You need one of the following authentication methods:
- **Microsoft Graph PowerShell session**: `Connect-MgGraph` with Application Administrator or Global Administrator role
- **Azure CLI session**: `az login` with appropriate permissions  
- **Direct access token**: Valid Microsoft Graph access token with application management permissions

## Why Use a Service Principal?

Service principals enable secure, automated access to Microsoft Entra ID:

- **🔄 Automation**: Run ScEntra on schedules without user interaction
- **🔒 Security**: Store credentials in secure vaults (Azure Key Vault, GitHub Secrets)
- **📋 Auditing**: Clear attribution of API calls to specific service identity
- **🎯 Least Privilege**: Grant only permissions needed for ScEntra analysis
- **⚡ No MFA**: Service principals bypass multi-factor authentication requirements
- **📊 Monitoring**: Dedicated identity for tracking and alerting

## Quick Start

### Step 1: Authenticate

Choose your preferred authentication method:

```powershell
# Option 1: Microsoft Graph PowerShell (for interactive setup)
Connect-MgGraph -Scopes "Application.ReadWrite.All", "Directory.Read.All"

# Option 2: Azure CLI (for command line users)
az login
az account set --subscription "your-subscription-id"

# Option 3: ScEntra's built-in device code flow
Connect-ScEntraGraph -UseDeviceCode -TenantId "your-tenant-id"

# Option 4: Direct token (advanced users)
$token = "your-access-token"
```

### Step 2: Import ScEntra and Create Service Principal

```powershell
# Import the ScEntra module
Import-Module ./ScEntra.psd1

# Create service principal with client secret
$sp = New-ScEntraServicePrincipal -DisplayName "ScEntra Production"

# Display the results
$sp | Format-List
```

**📋 Sample Output:**
```
DisplayName     : ScEntra Production
ApplicationId   : 12345678-1234-1234-1234-123456789abc
ObjectId        : 87654321-4321-4321-4321-cba987654321
TenantId        : abcdef12-3456-7890-abcd-ef1234567890
ClientSecret    : [REDACTED]
SecretExpiresOn : 12/10/2026 2:30:45 PM
ConsentUrl      : https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps...
```

**⚠️ CRITICAL**: Save the `ClientSecret` immediately - it cannot be retrieved later!

### Step 3: Grant Admin Consent

**Required!** Admin consent is mandatory for the Microsoft Graph application permissions:

1. **Use the provided URL**: Click the `ConsentUrl` from the output above
2. **Manual navigation**: 
   - Go to [Azure Portal](https://portal.azure.com) → **Entra ID** → **App registrations**
   - Find **ScEntra Production** → **API permissions** 
   - Click **Grant admin consent for [Your Tenant]**
3. **Confirm**: Click **Yes** to approve all permissions

### Step 4: Test the Connection

```powershell
# Connect using the new service principal
Connect-ScEntraGraph -TenantId $sp.TenantId -ClientId $sp.ApplicationId -ClientSecret $sp.ClientSecret

# Verify with a quick test by running a simple ScEntra command
# This will test the connection and permissions
Get-ScEntraEnvironmentSize
```

## Advanced Configuration

### Certificate-Based Authentication (Recommended for Production)

Certificates provide stronger security than client secrets:

```powershell
# Create a self-signed certificate (for development/testing)
$cert = New-SelfSignedCertificate `
    -Subject "CN=ScEntra-Production" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyExportPolicy Exportable `
    -KeySpec Signature `
    -NotAfter (Get-Date).AddYears(2)

# Export to PFX file
$certPassword = ConvertTo-SecureString -String "SecurePassword123!" -AsPlainText -Force
$certPath = "C:\certs\scentra-prod.pfx"
Export-PfxCertificate -Cert $cert -FilePath $certPath -Password $certPassword

# Create service principal with certificate
$sp = New-ScEntraServicePrincipal `
    -DisplayName "ScEntra Production Cert" `
    -CertificatePath $certPath `
    -CertificatePassword $certPassword

# Connect using certificate
# Connect using certificate
Connect-ScEntraGraph -TenantId $sp.TenantId -ClientId $sp.ApplicationId -CertificateThumbprint $sp.CertThumbprint
```

### Custom Secret Expiration

```powershell
# Create short-lived secret for testing
$sp = New-ScEntraServicePrincipal `
    -DisplayName "ScEntra Development" `
    -SecretExpirationMonths 3

# Create long-lived secret for production
$sp = New-ScEntraServicePrincipal `
    -DisplayName "ScEntra Production" `
    -SecretExpirationMonths 24  # Maximum allowed
```

### Using Existing Access Token

```powershell
# For environments with existing Graph tokens
$token = Get-ExistingGraphToken  # Your method to get token
$sp = New-ScEntraServicePrincipal -DisplayName "ScEntra" -AccessToken $token
```

## Required Permissions

The service principal receives these **Microsoft Graph Application Permissions** (automatically assigned, validated against actual Graph API endpoints):

| Permission | Purpose | Graph Endpoints Used |
|------------|---------|---------------------|
| **User.Read.All** | Read user accounts and profiles | `/v1.0/users` |
| **Group.Read.All** | Read group properties and ownership | `/v1.0/groups`, `/v1.0/groups/{id}/owners` |
| **GroupMember.Read.All** | Read group membership hierarchies | `/v1.0/groups/{id}/members`, `/v1.0/groups/{id}/transitiveMembers` |
| **Application.Read.All** | Read applications and service principals | `/v1.0/applications`, `/v1.0/servicePrincipals`, `/v1.0/servicePrincipals/{id}/appRoleAssignments` |
| **DelegatedPermissionGrant.Read.All** | Read OAuth2 permission grants | `/v1.0/servicePrincipals/{id}/oauth2PermissionGrants` |
| **RoleManagement.Read.Directory** | Read Entra ID role assignments | `/v1.0/directoryRoles`, `/v1.0/roleManagement/directory/roleDefinitions` |
| **RoleEligibilitySchedule.Read.Directory** | Read PIM eligible assignments | `/v1.0/roleManagement/directory/roleEligibilitySchedules` |
| **RoleAssignmentSchedule.Read.Directory** | Read PIM active assignments | `/v1.0/roleManagement/directory/roleAssignmentSchedules` |
| **PrivilegedAccess.Read.AzureADGroup** | Read PIM for Groups | `/v1.0/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances` |

**🔍 Key Points:**
- **9 permissions total** - All are **read-only** for maximum security
- **Zero write permissions** - Cannot modify your Entra ID environment
- **Admin consent required** - Must be approved by Global or Application Administrator
- **Least privilege design** - Only permissions actually used by ScEntra analysis

## Security Best Practices

### 1. Secure Credential Storage

**Never store credentials in plain text or scripts!**

```powershell
# ✅ Azure Key Vault (recommended for Azure environments)
Import-Module Az.KeyVault
Set-AzKeyVaultSecret -VaultName "MyCompanyVault" -Name "ScEntra-ClientSecret" `
    -SecretValue (ConvertTo-SecureString $sp.ClientSecret -AsPlainText -Force)

# Retrieve and use
$secret = Get-AzKeyVaultSecret -VaultName "MyCompanyVault" -Name "ScEntra-ClientSecret" -AsPlainText
Connect-ScEntraGraph -TenantId $sp.TenantId -ClientId $sp.ApplicationId -ClientSecret $secret

# ✅ GitHub Secrets (for GitHub Actions)
# Store in repository secrets: SCENTRA_TENANT_ID, SCENTRA_CLIENT_ID, SCENTRA_CLIENT_SECRET

# ✅ Environment variables (for local development)
$env:SCENTRA_TENANT_ID = $sp.TenantId
$env:SCENTRA_CLIENT_ID = $sp.ApplicationId  
$env:SCENTRA_CLIENT_SECRET = $sp.ClientSecret
```

### 2. Network Security and Conditional Access

Restrict where the service principal can authenticate from:

1. **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. **Create new policy** targeting your ScEntra service principal:
   ```
   Users and groups: Select your ScEntra service principal
   Cloud apps: Microsoft Graph
   Conditions: Configure trusted locations/IP ranges
   Grant: Block access from untrusted locations
   ```

### 3. Monitoring and Alerting

Set up monitoring for the service principal:

```powershell
# Query recent activity using Azure CLI or REST API
# Note: This requires additional setup for audit log access

# Alternative: Monitor via Azure Portal
# Go to Azure Portal > Entra ID > Enterprise Applications > [Your App] > Sign-in logs

# Set up alerts for:
# - Authentication from unexpected locations  
# - High volume API calls (>10,000/hour)
# - Failed authentication attempts
# - Permission changes to the service principal
```

### 4. Regular Credential Rotation

Implement automated rotation (recommended: every 6 months):

```powershell
# PowerShell script for rotation using REST API
function Update-ScEntraServicePrincipal {
    param($ApplicationId, $TenantId, $CurrentClientSecret)
    
    # Get access token with current credentials
    $tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Method POST -Body @{
        client_id = $ApplicationId
        client_secret = $CurrentClientSecret
        grant_type = "client_credentials"
        scope = "https://graph.microsoft.com/.default"
    }
    
    $headers = @{ Authorization = "Bearer $($tokenResponse.access_token)" }
    
    # Add new password credential
    $newSecretBody = @{
        passwordCredential = @{
            displayName = "Rotated Secret $(Get-Date -Format 'yyyy-MM-dd')"
            endDateTime = (Get-Date).AddMonths(12).ToString('yyyy-MM-ddTHH:mm:ssZ')
        }
    }
    
    $app = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/applications?`$filter=appId eq '$ApplicationId'" -Headers $headers
    $newSecret = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/applications/$($app.value[0].id)/addPassword" -Method POST -Headers $headers -Body ($newSecretBody | ConvertTo-Json) -ContentType "application/json"
    
    Write-Host "New client secret: $($newSecret.secretText)"
    Write-Host "Key ID: $($newSecret.keyId)"
    
    # Test new credential
    Connect-ScEntraGraph -ClientId $ApplicationId -ClientSecret $newSecret.secretText -TenantId $TenantId
    
    # After validation, remove old credential
    # Remove-RestMethod call for old key would go here
}
```

## Automation Examples

### Azure DevOps Pipeline

```yaml
# azure-pipelines.yml
trigger:
  schedules:
  - cron: "0 2 * * 1"  # Every Monday at 2 AM
    displayName: Weekly Security Scan
    branches:
      include:
      - main

variables:
- group: ScEntra-Secrets  # Variable group containing TENANT_ID, CLIENT_ID, CLIENT_SECRET

jobs:
- job: SecurityScan
  displayName: 'Run ScEntra Security Analysis'
  pool:
    vmImage: 'ubuntu-latest'
  
  steps:
  - task: PowerShell@2
    displayName: 'Install and Run ScEntra'
    inputs:
      targetType: 'inline'
      script: |
        # Install PowerShell modules
        Install-Module Microsoft.Graph.Authentication -Force -Scope CurrentUser
        
        # Import ScEntra
        Import-Module ./ScEntra.psd1
        
        # Connect using service principal
        Connect-ScEntraGraph -TenantId "$(TENANT_ID)" -ClientId "$(CLIENT_ID)" -ClientSecret "$(CLIENT_SECRET)"
        
        # Run analysis
        $report = Invoke-ScEntraAnalysis -RedactSensitiveInfo
        
        # Export report
        Export-ScEntraReport -Report $report -OutputPath "$(Build.ArtifactStagingDirectory)/scentra-report.html"
        
        # Display summary
        Write-Host "ScEntra analysis completed. Found $($report.EscalationRisks.Count) escalation risks."
      pwsh: true
      
  - task: PublishBuildArtifacts@1
    displayName: 'Publish Security Report'
    inputs:
      PathtoPublish: '$(Build.ArtifactStagingDirectory)'
      ArtifactName: 'ScEntra-Reports'
```

### GitHub Actions Workflow

```yaml
# .github/workflows/scentra-scan.yml
name: ScEntra Security Scan

on:
  schedule:
    - cron: '0 6 * * 1'  # Every Monday at 6 AM UTC
  workflow_dispatch:
  
env:
  SCENTRA_TENANT_ID: ${{ secrets.SCENTRA_TENANT_ID }}
  SCENTRA_CLIENT_ID: ${{ secrets.SCENTRA_CLIENT_ID }}  
  SCENTRA_CLIENT_SECRET: ${{ secrets.SCENTRA_CLIENT_SECRET }}

jobs:
  security-scan:
    name: Run ScEntra Security Analysis
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout Repository
      uses: actions/checkout@v4
      
    - name: Setup PowerShell
      run: |
        # Install PowerShell on Ubuntu
        sudo apt-get update
        sudo apt-get install -y wget apt-transport-https software-properties-common
        wget -q https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb
        sudo dpkg -i packages-microsoft-prod.deb
        sudo apt-get update
        sudo apt-get install -y powershell
        
    - name: Install Dependencies
      run: |
        pwsh -Command "Install-Module Microsoft.Graph.Authentication -Force -Scope CurrentUser"
        
    - name: Run ScEntra Analysis
      run: |
        pwsh -Command "
          Import-Module ./ScEntra.psd1
          Connect-ScEntraGraph -TenantId \$env:SCENTRA_TENANT_ID -ClientId \$env:SCENTRA_CLIENT_ID -ClientSecret \$env:SCENTRA_CLIENT_SECRET
          \$report = Invoke-ScEntraAnalysis -RedactSensitiveInfo
          Export-ScEntraReport -Report \$report -OutputPath './scentra-report.html'
          
          # Create summary
          \$summary = @\"
          ## ScEntra Security Analysis Results
          
          - **Analysis Date**: \$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')
          - **Escalation Risks Found**: \$(\$report.EscalationRisks.Count)
          - **High Severity**: \$(\$report.EscalationRisks | Where-Object Severity -eq 'High' | Measure-Object).Count
          - **Critical Severity**: \$(\$report.EscalationRisks | Where-Object Severity -eq 'Critical' | Measure-Object).Count
          
          [Download Full Report](./scentra-report.html)
          \"@
          
          \$summary | Out-File -FilePath './scan-summary.md' -Encoding UTF8
        "
        
    - name: Upload Security Report
      uses: actions/upload-artifact@v4
      with:
        name: scentra-security-report
        path: |
          scentra-report.html
          scan-summary.md
        retention-days: 90
        
    - name: Comment PR (if triggered by PR)
      if: github.event_name == 'pull_request'
      uses: actions/github-script@v7
      with:
        script: |
          const fs = require('fs');
          const summary = fs.readFileSync('./scan-summary.md', 'utf8');
          
          github.rest.issues.createComment({
            issue_number: context.issue.number,
            owner: context.repo.owner,
            repo: context.repo.repo,
            body: `🔒 **ScEntra Security Scan Results**\n\n${summary}`
          });
```

### Azure Automation Runbook

```powershell
# ScEntra-AutomationRunbook.ps1
<#
.DESCRIPTION
    Azure Automation runbook to run ScEntra analysis on a schedule
    
    Required Automation Variables:
    - ScEntra_TenantId
    - ScEntra_ClientId  
    - ScEntra_ClientSecret (encrypted)
    
    Required Automation Modules:
    - Microsoft.Graph.Authentication
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$StorageAccountName = "yourscentralogstorage",
    
    [Parameter(Mandatory = $false)] 
    [string]$ContainerName = "scentra-reports"
)

try {
    # Get automation variables
    $tenantId = Get-AutomationVariable -Name 'ScEntra_TenantId'
    $clientId = Get-AutomationVariable -Name 'ScEntra_ClientId'
    $clientSecret = Get-AutomationVariable -Name 'ScEntra_ClientSecret'
    
    Write-Output "Starting ScEntra security analysis..."
    
    # Import ScEntra module (upload to Automation Account)
    Import-Module ScEntra -Force
    
    # Connect to Microsoft Graph
    Connect-ScEntraGraph -TenantId $tenantId -ClientId $clientId -ClientSecret $clientSecret
    Write-Output "Connected to Microsoft Graph successfully"
    
    # Run analysis with redaction for automated scenarios
    $report = Invoke-ScEntraAnalysis -RedactSensitiveInfo -PerformanceProfile "Medium"
    Write-Output "ScEntra analysis completed. Found $($report.EscalationRisks.Count) escalation risks"
    
    # Export report
    $reportFileName = "ScEntra-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
    $tempPath = Join-Path $env:TEMP $reportFileName
    Export-ScEntraReport -Report $report -OutputPath $tempPath
    
    # Upload to Azure Storage (optional)
    if ($StorageAccountName -and $ContainerName) {
        $storageContext = New-AzStorageContext -StorageAccountName $StorageAccountName -UseConnectedAccount
        Set-AzStorageBlobContent -File $tempPath -Container $ContainerName -Blob $reportFileName -Context $storageContext
        Write-Output "Report uploaded to Azure Storage: $StorageAccountName/$ContainerName/$reportFileName"
    }
    
    # Generate summary for output
    $criticalRisks = ($report.EscalationRisks | Where-Object Severity -eq 'Critical').Count
    $highRisks = ($report.EscalationRisks | Where-Object Severity -eq 'High').Count
    
    $output = @{
        Status = "Success"
        AnalysisDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC"
        TotalRisks = $report.EscalationRisks.Count
        CriticalRisks = $criticalRisks  
        HighRisks = $highRisks
        ReportLocation = if ($StorageAccountName) { "$StorageAccountName/$ContainerName/$reportFileName" } else { $tempPath }
    }
    
    Write-Output ($output | ConvertTo-Json -Depth 2)
    
    # Send alert if critical risks found
    if ($criticalRisks -gt 0) {
        Write-Warning "ALERT: $criticalRisks critical privilege escalation risks detected!"
    }
}
catch {
    Write-Error "ScEntra automation failed: $($_.Exception.Message)"
    throw
}
```

### Azure Function (Serverless)

```powershell
# ScEntra-Function/run.ps1
using namespace System.Net

param($Request, $TriggerMetadata)

try {
    # Get configuration from environment variables
    $tenantId = $env:SCENTRA_TENANT_ID
    $clientId = $env:SCENTRA_CLIENT_ID  
    $clientSecret = $env:SCENTRA_CLIENT_SECRET
    
    if (-not $tenantId -or -not $clientId -or -not $clientSecret) {
        throw "Missing required environment variables: SCENTRA_TENANT_ID, SCENTRA_CLIENT_ID, SCENTRA_CLIENT_SECRET"
    }
    
    # Import ScEntra module (included in function package)
    Import-Module ./ScEntra/ScEntra.psd1 -Force
    
    # Connect and run analysis
    Connect-ScEntraGraph -TenantId $tenantId -ClientId $clientId -ClientSecret $clientSecret
    $report = Invoke-ScEntraAnalysis -RedactSensitiveInfo -PerformanceProfile "Small"
    
    # Create response
    $response = @{
        status = "success"
        timestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
        summary = @{
            totalRisks = $report.EscalationRisks.Count
            criticalRisks = ($report.EscalationRisks | Where-Object Severity -eq 'Critical').Count
            highRisks = ($report.EscalationRisks | Where-Object Severity -eq 'High').Count
        }
        topRisks = $report.EscalationRisks | 
                   Sort-Object @{Expression = {if($_.Severity -eq 'Critical') {0} elseif($_.Severity -eq 'High') {1} else {2}}} |
                   Select-Object -First 5 -Property RiskType, Severity, Description
    }
    
    # Return JSON response
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::OK
        Body = $response | ConvertTo-Json -Depth 5
        Headers = @{ "Content-Type" = "application/json" }
    })
}
catch {
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::InternalServerError
        Body = @{ 
            status = "error"
            message = $_.Exception.Message
            timestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
        } | ConvertTo-Json
        Headers = @{ "Content-Type" = "application/json" }
    })
}
```

## Troubleshooting

### Common Issues and Solutions

#### ❌ "Insufficient privileges to complete the operation"
**Cause**: Admin consent hasn't been granted for the Microsoft Graph permissions.  
**Solution**: 
1. Use the consent URL from the service principal creation output
2. Or manually grant consent: Azure Portal → Entra ID → App registrations → [Your App] → API permissions → Grant admin consent

#### ❌ "The user or administrator has not consented to use the application"  
**Cause**: First authentication attempt before admin consent.  
**Solution**: Grant admin consent first, then retry authentication.

#### ❌ "Invalid client secret provided"
**Cause**: Client secret expired, incorrect, or contains special characters.  
**Solution**:
```powershell
# Create new secret using REST API
$tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Method POST -Body @{
    client_id = $appId
    client_secret = $currentSecret  # Use existing valid secret
    grant_type = "client_credentials"
    scope = "https://graph.microsoft.com/.default"
}

$headers = @{ Authorization = "Bearer $($tokenResponse.access_token)" }
$app = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/applications?`$filter=appId eq '$appId'" -Headers $headers

$newSecretBody = @{
    passwordCredential = @{
        endDateTime = (Get-Date).AddMonths(12).ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
}

$newCred = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/applications/$($app.value[0].id)/addPassword" -Method POST -Headers $headers -Body ($newSecretBody | ConvertTo-Json) -ContentType "application/json"
```

#### ❌ "Certificate validation failed"
**Cause**: Certificate expired, not trusted, or wrong format.  
**Solution**:
```powershell
# Check certificate validity  
$cert = Get-PfxCertificate -FilePath "C:\certs\scentra.pfx"
Write-Host "Valid from: $($cert.NotBefore)"
Write-Host "Valid until: $($cert.NotAfter)" 
Write-Host "Thumbprint: $($cert.Thumbprint)"

# Verify certificate chain
$cert.Verify()  # Should return True
```

#### ❌ "No access token available"
**Cause**: No active authentication session found.  
**Solutions**:
```powershell
# Option 1: Connect with Microsoft Graph PowerShell
Connect-MgGraph -Scopes "Application.ReadWrite.All"

# Option 2: Use Azure CLI
az login
az account set --subscription "your-subscription"

# Option 3: Provide token directly
$token = "your-access-token"
New-ScEntraServicePrincipal -AccessToken $token
```

#### ❌ "Graph API call failed: Forbidden"
**Cause**: Insufficient permissions to create applications.  
**Solution**: Ensure your account has **Application Administrator** or **Global Administrator** role.

### Validation and Testing

#### Test Service Principal Creation
```powershell
# Using REST API to verify the service principal was created correctly
$tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Method POST -Body @{
    client_id = $clientId
    client_secret = $clientSecret
    grant_type = "client_credentials"
    scope = "https://graph.microsoft.com/.default"
}

$headers = @{ Authorization = "Bearer $($tokenResponse.access_token)" }

# Get service principal details
$sp = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$clientId'" -Headers $headers
$app = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/applications?`$filter=appId eq '$clientId'" -Headers $headers

Write-Host "Service Principal: $($sp.value[0].displayName)"
Write-Host "Application: $($app.value[0].displayName)"

# Check assigned permissions
$app.value[0].requiredResourceAccess | ForEach-Object {
    Write-Host "Resource App ID: $($_.resourceAppId)"
    $_.resourceAccess | ForEach-Object {
        Write-Host "  Permission ID: $($_.id) (Type: $($_.type))"
    }
}
```

#### Test Authentication
```powershell
# Test service principal authentication
try {
    Connect-ScEntraGraph -TenantId $tenantId -ClientId $clientId -ClientSecret $clientSecret
    
    # Simple test call using ScEntra
    $envSize = Get-ScEntraEnvironmentSize
    Write-Host "✅ Authentication successful. Environment: $($envSize.ProfileName)" -ForegroundColor Green
    
    Write-Host "✅ Connection test completed successfully" -ForegroundColor Green
}
catch {
    Write-Error "❌ Authentication failed: $($_.Exception.Message)"
}
```

## Managing Service Principals

### View Current Service Principals
```powershell
# Using REST API to list ScEntra service principals
# Note: Requires administrative access token
$adminToken = "your-admin-token"  # Get this from Connect-MgGraph or similar
$headers = @{ Authorization = "Bearer $adminToken" }

# List service principals with ScEntra in the name
$servicePrincipals = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=startswith(displayName,'ScEntra')" -Headers $headers
$servicePrincipals.value | Select-Object displayName, appId, id, servicePrincipalType
```

### Update Service Principal
```powershell
# Rotate client secret using REST API
# First, authenticate with current credentials
$currentTokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Method POST -Body @{
    client_id = $appId
    client_secret = $currentSecret
    grant_type = "client_credentials"
    scope = "https://graph.microsoft.com/.default"
}

$headers = @{ Authorization = "Bearer $($currentTokenResponse.access_token)" }

# Get application object
$app = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/applications?`$filter=appId eq '$appId'" -Headers $headers

# Add new password credential
$newSecretBody = @{
    passwordCredential = @{
        displayName = "Rotated Secret $(Get-Date -Format 'yyyy-MM-dd')"
        endDateTime = (Get-Date).AddMonths(12).ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
}

$newPassword = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/applications/$($app.value[0].id)/addPassword" -Method POST -Headers $headers -Body ($newSecretBody | ConvertTo-Json) -ContentType "application/json"

Write-Host "New client secret: $($newPassword.secretText)"
Write-Host "Key ID: $($newPassword.keyId)"

# After updating all consumers, remove old password
# Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/applications/$($app.value[0].id)/removePassword" -Method POST -Headers $headers -Body (@{keyId=$oldKeyId} | ConvertTo-Json) -ContentType "application/json"
```

### Delete Service Principal
```powershell
# ⚠️ WARNING: This will permanently delete the service principal
# Using REST API with administrative token
$adminToken = "your-admin-token"
$headers = @{ Authorization = "Bearer $adminToken" }

# Get application
$app = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/applications?`$filter=displayName eq 'ScEntra Production'" -Headers $headers

if ($app.value.Count -gt 0) {
    # Confirm before deletion
    $confirm = Read-Host "Delete service principal '$($app.value[0].displayName)'? (yes/no)"
    if ($confirm -eq 'yes') {
        Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/applications/$($app.value[0].id)" -Method DELETE -Headers $headers
        Write-Host "✅ Service principal deleted successfully"
    } else {
        Write-Host "❌ Deletion cancelled"
    }
} else {
    Write-Host "Service principal not found"
}
```

## Compliance and Governance

### Regular Security Review Checklist

**Monthly Reviews:**
- [ ] Verify service principal is still needed
- [ ] Check for any unusual authentication patterns  
- [ ] Review API call volumes in Azure AD logs
- [ ] Ensure credentials haven't been exposed

**Quarterly Reviews:**
- [ ] Rotate client secrets/certificates
- [ ] Review and validate all assigned permissions
- [ ] Update Conditional Access policies if needed
- [ ] Document any changes in security policies

**Annual Reviews:**
- [ ] Full security assessment of service principal usage
- [ ] Review integration with other systems
- [ ] Update disaster recovery procedures
- [ ] Validate backup and restore capabilities

### Audit Logging
```powershell
# PowerShell script to generate audit report using REST API
function Get-ScEntraServicePrincipalAudit {
    param(
        [Parameter(Mandatory)]
        [string]$ServicePrincipalObjectId,
        
        [Parameter(Mandatory)]
        [string]$AdminAccessToken,
        
        [Parameter(Mandatory = $false)]
        [int]$DaysBack = 30
    )
    
    $headers = @{ Authorization = "Bearer $AdminAccessToken" }
    $startDate = (Get-Date).AddDays(-$DaysBack).ToString('yyyy-MM-ddTHH:mm:ssZ')
    
    try {
        # Note: Audit log access requires specific permissions and may need Microsoft Graph PowerShell SDK
        Write-Host "For comprehensive audit logs, use Azure Portal:" -ForegroundColor Yellow
        Write-Host "Portal > Entra ID > Enterprise Applications > [Your App] > Sign-in logs" -ForegroundColor Gray
        Write-Host "Portal > Entra ID > Audit logs > Filter by Service Principal" -ForegroundColor Gray
        
        # Basic service principal info
        $sp = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$ServicePrincipalObjectId" -Headers $headers
        
        return @{
            ServicePrincipalName = $sp.displayName
            ApplicationId = $sp.appId
            CreatedDateTime = $sp.createdDateTime
            AccountEnabled = $sp.accountEnabled
            Note = "For detailed sign-in and audit logs, use Azure Portal or Microsoft Graph PowerShell SDK with appropriate permissions"
        }
    }
    catch {
        Write-Error "Failed to get audit information: $($_.Exception.Message)"
    }
}

# Usage (requires admin token)
# $audit = Get-ScEntraServicePrincipalAudit -ServicePrincipalObjectId $sp.ObjectId -AdminAccessToken $adminToken
# $audit | ConvertTo-Json -Depth 3
```

## Additional Resources

### Documentation Links
- 📘 [Microsoft Graph API Permissions Reference](https://learn.microsoft.com/en-us/graph/permissions-reference) - Complete permission catalog
- 🔐 [Azure AD Service Principals Guide](https://learn.microsoft.com/en-us/azure/active-directory/develop/app-objects-and-service-principals) - Core concepts  
- 🎫 [Certificate Credentials Best Practices](https://learn.microsoft.com/en-us/azure/active-directory/develop/active-directory-certificate-credentials) - Security recommendations
- 🔑 [Azure Key Vault Integration](https://learn.microsoft.com/en-us/azure/key-vault/general/best-practices) - Secure credential storage
- 🛡️ [Conditional Access for Service Principals](https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/concept-conditional-access-cloud-apps) - Network restrictions

### ScEntra Resources  
- 🏠 **GitHub Repository**: [https://github.com/azurekid/Scentra](https://github.com/azurekid/Scentra)
- 📖 **Documentation**: [Main README](./README.md) | [Quick Start Guide](./QUICKSTART.md)  
- 🐛 **Issues & Support**: [GitHub Issues](https://github.com/azurekid/Scentra/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/azurekid/Scentra/discussions)

### Community and Support
- 🎯 **Feature Requests**: Submit via GitHub Issues with the `enhancement` label
- 🔧 **Bug Reports**: Include ScEntra version, PowerShell version, and error details
- 🤝 **Contributing**: See [CONTRIBUTING.md](./CONTRIBUTING.md) for contribution guidelines
- 📧 **Security Issues**: Report privately via GitHub Security tab

### Example Scripts Repository
Find complete automation examples at: [ScEntra-Examples](https://github.com/azurekid/ScEntra-Examples) *(planned)*

---

## Summary

The modernized `New-ScEntraServicePrincipal` function eliminates dependencies on Az PowerShell modules and provides:

**✅ Key Benefits:**
- **Zero external dependencies** - Uses only built-in PowerShell REST capabilities  
- **Flexible authentication** - Works with Graph PowerShell, Azure CLI, or direct tokens
- **Production ready** - Certificate support, proper error handling, audit logging
- **Automation friendly** - Perfect for CI/CD pipelines and serverless functions

**🔒 Security First:**
- **Read-only permissions** - Cannot modify your Entra ID environment
- **Least privilege principle** - Only 9 specific permissions actually used by ScEntra
- **Admin consent required** - Explicit approval process for all permissions
- **Comprehensive monitoring** - Built-in audit logging and alerting capabilities

**🚀 Ready for Scale:**
Whether you're running ScEntra manually, in automation pipelines, or enterprise environments, this guide provides the foundation for secure, maintainable service principal management.

**Next Steps:**
1. Create your service principal using the quick start guide
2. Implement secure credential storage appropriate for your environment  
3. Set up monitoring and alerting for the service principal
4. Schedule regular security reviews and credential rotation

For additional help or advanced scenarios, check the resources above or open an issue on GitHub.
