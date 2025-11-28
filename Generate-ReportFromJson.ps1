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

# Redact PII if requested
if ($RedactPII) {
    Write-Host "Redacting PII data..." -ForegroundColor Yellow
    
    # Function to generate a hash-based obfuscated name
    function Get-RedactedName {
        param([string]$original)
        if ([string]::IsNullOrEmpty($original)) { return $original }
        $hash = [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($original))).Replace("-", "").Substring(0,8)
        return "REDACTED_$hash"
    }
    
    # Function to redact email-like strings
    function Get-RedactedEmail {
        param([string]$email)
        if ([string]::IsNullOrEmpty($email)) { return $email }
        if ($email -notmatch '@') { return Get-RedactedName $email }
        $parts = $email -split '@'
        $local = $parts[0]
        $domain = $parts[1]
        $len = $local.Length
        if ($len -le 1) {
            $redactedLocal = $local
        } elseif ($len -le 4) {
            $redactedLocal = $local[0] + '.' + $local[-1]
        } else {
            $redactedLocal = $local.Substring(0,2) + '..' + $local.Substring($len-2)
        }
        if ($domain -like '*.onmicrosoft.com') {
            $newDomain = 'redacted.onmicrosoft.com'
        } else {
            $newDomain = 'redacted'
        }
        return "$redactedLocal@$newDomain"
    }
    
    # Redact users
    $jsonData.Users = $jsonData.Users | ForEach-Object {
        $user = $_
        $user.DisplayName = Get-RedactedName $user.DisplayName
        $user.UserPrincipalName = Get-RedactedEmail $user.UserPrincipalName
        if ($user.Mail) { $user.Mail = Get-RedactedEmail $user.Mail }
        $user
    }
    
    # Redact groups
    $jsonData.Groups = $jsonData.Groups | ForEach-Object {
        $group = $_
        $group.DisplayName = Get-RedactedName $group.DisplayName
        $group
    }
    
    # Redact service principals
    $jsonData.ServicePrincipals = $jsonData.ServicePrincipals | ForEach-Object {
        $sp = $_
        $sp.DisplayName = Get-RedactedName $sp.DisplayName
        $sp
    }
    
    # Redact app registrations
    $jsonData.AppRegistrations = $jsonData.AppRegistrations | ForEach-Object {
        $app = $_
        $app.DisplayName = Get-RedactedName $app.DisplayName
        $app
    }
    
    # Redact organization info
    if ($jsonData.OrganizationInfo) {
        $jsonData.OrganizationInfo.DisplayName = Get-RedactedName $jsonData.OrganizationInfo.DisplayName
        if ($jsonData.OrganizationInfo.VerifiedDomains) {
            $jsonData.OrganizationInfo.VerifiedDomains = $jsonData.OrganizationInfo.VerifiedDomains | ForEach-Object { Get-RedactedName $_ }
        }
    }
    
    # Redact escalation risks (entity names, but keep role names)
    $jsonData.EscalationRisks = $jsonData.EscalationRisks | ForEach-Object {
        $risk = $_
        if ($risk.UserName) { $risk.UserName = Get-RedactedName $risk.UserName }
        if ($risk.GroupName) { $risk.GroupName = Get-RedactedName $risk.GroupName }
        if ($risk.ServicePrincipalName) { $risk.ServicePrincipalName = Get-RedactedName $risk.ServicePrincipalName }
        if ($risk.AppName) { $risk.AppName = Get-RedactedName $risk.AppName }
        $risk
    }
    
    # Redact graph data nodes
    if ($jsonData.GraphData -and $jsonData.GraphData.nodes) {
        # Collect role names to preserve
        $roleNames = @()
        $roleNames += $jsonData.RoleAssignments | ForEach-Object { $_.RoleName } | Select-Object -Unique
        $roleNames += $jsonData.PIMAssignments | ForEach-Object { $_.RoleName } | Select-Object -Unique
        $roleNames = $roleNames | Where-Object { $_ } | Select-Object -Unique
        
        $jsonData.GraphData.nodes = $jsonData.GraphData.nodes | ForEach-Object {
            $node = $_
            # Removed nested data check
                if ($node.userPrincipalName) { $node.data.userPrincipalName = Get-RedactedEmail $node.data.userPrincipalName }
                if ($node.mail) { $node.data.mail = Get-RedactedEmail $node.data.mail }
            }
            if ($node.label -and $roleNames -notcontains $node.label) { $node.label = Get-RedactedName $node.label }
            if ($node.title -and $roleNames -notcontains $node.title) { $node.title = Get-RedactedName $node.title }
            $node
        }
    }
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
