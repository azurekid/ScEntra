<#
.SYNOPSIS
    Updates graph-permissions.csv with all Microsoft Graph permissions from the official documentation.

.DESCRIPTION
    This script fetches the latest Microsoft Graph permissions from Microsoft Learn documentation,
    compares them with the existing graph-permissions.csv file, and adds any missing permissions.

.NOTES
    Author: ScEntra
    Date: 2025-01-30
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$csvPath = Join-Path $PSScriptRoot 'Private' 'graph-permissions.csv'

# Import the ScEntra module to access Graph helpers
Write-Host "Importing ScEntra module..." -ForegroundColor Cyan
Import-Module (Join-Path $PSScriptRoot 'ScEntra.psd1') -Force

# Connect to Microsoft Graph if not already connected
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
Connect-ScEntraGraph | Out-Null

Write-Host "Loading existing permissions from CSV..." -ForegroundColor Cyan
$existingPermissions = Import-Csv -Path $csvPath

Write-Host "Current permission count: $($existingPermissions.Count)" -ForegroundColor Yellow
Write-Host "  - Application (Role): $(($existingPermissions | Where-Object Type -eq 'Role').Count)" -ForegroundColor Gray
Write-Host "  - Delegated (Scope): $(($existingPermissions | Where-Object Type -eq 'Scope').Count)" -ForegroundColor Gray

# Create a hashtable for faster lookup
$existingLookup = @{}
foreach ($perm in $existingPermissions) {
    $key = "$($perm.Permission)|$($perm.Type)"
    $existingLookup[$key] = $perm
}

Write-Host "`nFetching latest permissions from Microsoft Graph API..." -ForegroundColor Cyan

try {
    # Get access token from Az.Accounts
    Write-Host "`nFetching permissions from Microsoft Graph API..." -ForegroundColor Cyan
    
    $token = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com" -ErrorAction Stop
    if (-not $token) {
        throw "Failed to get access token. Please run Connect-ScEntraGraph first."
    }
    
    $accessToken = $token.Token | ConvertFrom-SecureString -AsPlainText
    
    # Query Microsoft Graph service principal to get all permissions
    $uri = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '00000003-0000-0000-c000-000000000000'&`$select=appRoles,oauth2PermissionScopes"
    
    $headers = @{
        'Authorization' = "Bearer $accessToken"
        'Content-Type' = 'application/json'
    }
    
    $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method GET
    
    if (-not $response -or -not $response.value) {
        throw "Failed to retrieve Microsoft Graph service principal data"
    }
    
    $graphSP = $response.value[0]
    
    # Process Application permissions (appRoles)
    $newPermissions = @()
    
    Write-Host "`nProcessing Application permissions..." -ForegroundColor Cyan
    foreach ($appRole in $graphSP.appRoles) {
        $key = "$($appRole.value)|Role"
        
        if (-not $existingLookup.ContainsKey($key)) {
            Write-Host "  [NEW] $($appRole.value)" -ForegroundColor Green
            
            $newPermissions += [PSCustomObject]@{
                Resource             = 'Microsoft Graph'
                Permission           = $appRole.value
                PermissionId         = $appRole.id
                PermissionValue      = $appRole.value
                Type                 = 'Role'
                Audience             = 'Application'
                DisplayName          = $appRole.displayName
                Description          = $appRole.description
                AdminConsentRequired = 'Yes'
                SectionId            = $appRole.value.ToLower() -replace '\.', ''
            }
        }
    }
    
    Write-Host "`nProcessing Delegated permissions..." -ForegroundColor Cyan
    foreach ($scope in $graphSP.oauth2PermissionScopes) {
        $key = "$($scope.value)|Scope"
        
        if (-not $existingLookup.ContainsKey($key)) {
            Write-Host "  [NEW] $($scope.value)" -ForegroundColor Green
            
            $adminConsent = if ($scope.type -eq 'Admin') { 'Yes' } else { 'No' }
            
            $newPermissions += [PSCustomObject]@{
                Resource             = 'Microsoft Graph'
                Permission           = $scope.value
                PermissionId         = $scope.id
                PermissionValue      = $scope.value
                Type                 = 'Scope'
                Audience             = 'Delegated'
                DisplayName          = $scope.adminConsentDisplayName
                Description          = $scope.adminConsentDescription
                AdminConsentRequired = $adminConsent
                SectionId            = $scope.value.ToLower() -replace '\.', ''
            }
        }
    }
    
    if ($newPermissions.Count -eq 0) {
        Write-Host "`nNo new permissions found. CSV is up to date!" -ForegroundColor Green
        return
    }
    
    Write-Host "`nFound $($newPermissions.Count) new permissions:" -ForegroundColor Yellow
    Write-Host "  - Application (Role): $(($newPermissions | Where-Object Type -eq 'Role').Count)" -ForegroundColor Gray
    Write-Host "  - Delegated (Scope): $(($newPermissions | Where-Object Type -eq 'Scope').Count)" -ForegroundColor Gray
    
    # Combine existing and new permissions
    $allPermissions = $existingPermissions + $newPermissions
    
    # Sort by Permission name and Type
    $allPermissions = $allPermissions | Sort-Object Permission, Type
    
    # Backup existing CSV
    $backupPath = $csvPath -replace '\.csv$', "_backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    Write-Host "`nCreating backup: $backupPath" -ForegroundColor Cyan
    Copy-Item -Path $csvPath -Destination $backupPath
    
    # Export updated CSV
    Write-Host "Exporting updated CSV..." -ForegroundColor Cyan
    $allPermissions | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    
    Write-Host "`nSuccess! Updated CSV now contains $($allPermissions.Count) permissions." -ForegroundColor Green
    Write-Host "Backup saved to: $backupPath" -ForegroundColor Gray
    
} catch {
    Write-Host "`nERROR: $_" -ForegroundColor Red
    Write-Host "`nThis script requires Microsoft Graph authentication." -ForegroundColor Yellow
    Write-Host "Please run the following commands first:" -ForegroundColor Yellow
    Write-Host "  Import-Module ./ScEntra.psd1 -Force" -ForegroundColor White
    Write-Host "  Connect-ScEntraGraph -Scopes 'Application.Read.All'" -ForegroundColor White
    Write-Host "`nThen run this script again." -ForegroundColor Yellow
    exit 1
}
