#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Regenerates an HTML report from an existing JSON export
    
.DESCRIPTION
    Takes a ScEntra JSON export file and regenerates the HTML report with the latest template
    
.PARAMETER JsonPath
    Path to the JSON file to regenerate from
    
.EXAMPLE
    ./Generate-ReportFromJson.ps1 -JsonPath "./ScEntra-Report-20251120-110942.json"
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$JsonPath
)

# Import the module
Import-Module ./ScEntra.psd1 -Force

# Check if JSON file exists
if (-not (Test-Path $JsonPath)) {
    Write-Error "JSON file not found: $JsonPath"
    exit 1
}

# Read the JSON data
Write-Host "Reading JSON data from: $JsonPath" -ForegroundColor Cyan
$jsonData = Get-Content $JsonPath -Raw | ConvertFrom-Json

# Convert GraphData from PSCustomObject to hashtable if it exists
$graphData = $null
if ($jsonData.GraphData) {
    $graphData = @{
        nodes = @($jsonData.GraphData.nodes)
        edges = @($jsonData.GraphData.edges)
    }
}

# Determine output HTML path
$outputPath = $JsonPath -replace '\.json$', '-regenerated.html'

Write-Host "Regenerating HTML report..." -ForegroundColor Cyan

# Call the export function with the data from JSON
$reportPath = Export-ScEntraReport `
    -Users $jsonData.Users `
    -Groups $jsonData.Groups `
    -ServicePrincipals $jsonData.ServicePrincipals `
    -AppRegistrations $jsonData.AppRegistrations `
    -RoleAssignments $jsonData.RoleAssignments `
    -PIMAssignments $jsonData.PIMAssignments `
    -EscalationRisks $jsonData.EscalationRisks `
    -GraphData $graphData `
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
