#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Regenerates an HTML report from an existing JSON export
    
.DESCRIPTION
    Takes a ScEntra JSON export file and regenerates the HTML report with the latest template
    
.PARAMETER JsonPath
    Path to the JSON file to regenerate from
    
.PARAMETER RedactPII
    Redact personally identifiable information (names, UPNs, emails, etc.) from the report
    
.EXAMPLE
    ./Generate-ReportFromJson.ps1 -JsonPath "./ScEntra-Report-20251120-110942.json"
    
.EXAMPLE
    ./Generate-ReportFromJson.ps1 -JsonPath "./ScEntra-Report-20251120-110942.json" -RedactPII
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$JsonPath,
    [Parameter(Mandatory = $false)]
    [switch]$RedactPII
)

# Import the module and shared helpers
Import-Module ./ScEntra.psd1 -Force
$redactionHelperPath = Join-Path $PSScriptRoot "Private/RedactionHelpers.ps1"
if (Test-Path $redactionHelperPath) {
    . $redactionHelperPath
}

# Check if JSON file exists
if (-not (Test-Path $JsonPath)) {
    Write-Error "JSON file not found: $JsonPath"
    exit 1
}

# Read the JSON data
Write-Host "Reading JSON data from: $JsonPath" -ForegroundColor Cyan
$jsonData = Get-Content $JsonPath -Raw | ConvertFrom-Json

# Redact PII if requested
if ($RedactPII) {
    Write-Host "Redacting PII data..." -ForegroundColor Yellow
    $redacted = Invoke-ScEntraDataRedaction `
        -Users $jsonData.Users `
        -Groups $jsonData.Groups `
        -ServicePrincipals $jsonData.ServicePrincipals `
        -AppRegistrations $jsonData.AppRegistrations `
        -RoleAssignments $jsonData.RoleAssignments `
        -PIMAssignments $jsonData.PIMAssignments `
        -EscalationRisks $jsonData.EscalationRisks `
        -GraphData $jsonData.GraphData `
        -OrganizationInfo $jsonData.OrganizationInfo

    if ($redacted.Users) { $jsonData.Users = $redacted.Users }
    if ($redacted.Groups) { $jsonData.Groups = $redacted.Groups }
    if ($redacted.ServicePrincipals) { $jsonData.ServicePrincipals = $redacted.ServicePrincipals }
    if ($redacted.AppRegistrations) { $jsonData.AppRegistrations = $redacted.AppRegistrations }
    if ($redacted.EscalationRisks) { $jsonData.EscalationRisks = $redacted.EscalationRisks }
    if ($redacted.GraphData) { $jsonData.GraphData = $redacted.GraphData }
    if ($redacted.OrganizationInfo) { $jsonData.OrganizationInfo = $redacted.OrganizationInfo }
}

# Convert GraphData from PSCustomObject to hashtable if it exists
$graphData = $null
if ($jsonData.GraphData) {
    $graphData = @{
        nodes = @($jsonData.GraphData.nodes)
        edges = @($jsonData.GraphData.edges)
    }
}

# Determine output HTML path
$suffix = if ($RedactPII) { '-redacted' } else { '-regenerated' }
$outputPath = $JsonPath -replace '\.json$', "$suffix.html"

Write-Host "Regenerating HTML report..." -ForegroundColor Cyan

# Filter escalation risks to exclude empty groups and non-highly-privileged roles
$highPrivilegeRoles = @(
    'Global Administrator',
    'Privileged Role Administrator',
    'Security Administrator',
    'Cloud Application Administrator',
    'Application Administrator',
    'User Administrator',
    'Exchange Administrator',
    'SharePoint Administrator'
)

$filteredRisks = $jsonData.EscalationRisks | Where-Object {
    $risk = $_
    
    # Filter RoleEnabledGroup risks
    if ($risk.RiskType -eq 'RoleEnabledGroup') {
        # Exclude if group has 0 members or role is not highly privileged
        return ($risk.MemberCount -gt 0) -and ($highPrivilegeRoles -contains $risk.RoleName)
    }
    
    # Keep all other risk types
    return $true
}

Write-Host "Filtered risks: $($jsonData.EscalationRisks.Count) -> $($filteredRisks.Count)" -ForegroundColor Yellow

# Convert OrganizationInfo from PSCustomObject to hashtable if needed
$orgInfo = $null
if ($jsonData.OrganizationInfo) {
    if ($jsonData.OrganizationInfo -is [hashtable]) {
        $orgInfo = $jsonData.OrganizationInfo
    } else {
        $orgInfo = @{}
        $jsonData.OrganizationInfo.PSObject.Properties | ForEach-Object {
            $orgInfo[$_.Name] = $_.Value
        }
    }
}

# Call the export function with the data from JSON
$reportPath = Export-ScEntraReport `
    -Users $jsonData.Users `
    -Groups $jsonData.Groups `
    -ServicePrincipals $jsonData.ServicePrincipals `
    -AppRegistrations $jsonData.AppRegistrations `
    -RoleAssignments $jsonData.RoleAssignments `
    -PIMAssignments $jsonData.PIMAssignments `
    -EscalationRisks $filteredRisks `
    -GraphData $graphData `
    -OrganizationInfo $orgInfo `
    -OutputPath $outputPath

if ($reportPath) {
    Write-Host "`n✓ Report regenerated successfully!" -ForegroundColor Green
    Write-Host "Location: $reportPath" -ForegroundColor Cyan
    
    # Open in browser
    Invoke-Item $reportPath
}
else {
    Write-Error "Failed to regenerate report"
    exit 1
}
