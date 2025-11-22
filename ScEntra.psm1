#Requires -Version 7.0

<#
.SYNOPSIS
    ScEntra - Scan Entra for risk in role assignments and escalation paths

.DESCRIPTION
    This module provides functions to inventory Entra ID objects (users, groups, service principals, app registrations)
    and analyze privilege escalation risks through role assignments, PIM, and nested group memberships.
    
    This module uses direct Microsoft Graph REST API endpoints for maximum compatibility and control.
#>

#region Module Initialization
$privateFolder = Join-Path -Path $PSScriptRoot -ChildPath 'Private'
if (Test-Path $privateFolder) {
    Get-ChildItem -Path $privateFolder -Filter '*.ps1' | ForEach-Object { . $_.FullName }
}

$publicFolder = Join-Path -Path $PSScriptRoot -ChildPath 'Public'
if (Test-Path $publicFolder) {
    Get-ChildItem -Path $publicFolder -Filter '*.ps1' | ForEach-Object { . $_.FullName }
}
#endregion

# Export module members
Export-ModuleMember -Function @(
    'Connect-ScEntraGraph'
    'Invoke-ScEntraAnalysis'
    'Get-ScEntraServicePrincipals'
    'Get-ScEntraAppRegistrations'
    'Get-ScEntraRoleAssignments'
    'Get-ScEntraPIMAssignments'
    'Get-ScEntraEscalationPaths'
    'Export-ScEntraReport',
    'Invoke-JsonAnonymizer'
)