function Export-ScEntraReport {
    <#
    .SYNOPSIS
        Exports analysis results to HTML report with visualizations

    .DESCRIPTION
        Generates an interactive HTML report with charts and tables showing the inventory
        and escalation path analysis

    .PARAMETER Users
        Array of users

    .PARAMETER Groups
        Array of groups

    .PARAMETER ServicePrincipals
        Array of service principals

    .PARAMETER AppRegistrations
        Array of app registrations

    .PARAMETER RoleAssignments
        Array of role assignments

    .PARAMETER PIMAssignments
        Array of PIM assignments

    .PARAMETER EscalationRisks
        Array of escalation risks

    .PARAMETER GraphData
        Graph nodes and edges describing escalation relationships

    .PARAMETER OutputPath
        Path where to save the HTML report

    .EXAMPLE
        Export-ScEntraReport -Users $users -Groups $groups -OutputPath "C:\Reports\entra-report.html"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][array]$Users,
        [Parameter(Mandatory = $true)][array]$Groups,
        [Parameter(Mandatory = $true)][array]$ServicePrincipals,
        [Parameter(Mandatory = $true)][array]$AppRegistrations,
        [Parameter(Mandatory = $true)][array]$RoleAssignments,
        [Parameter(Mandatory = $false)][array]$PIMAssignments = @(),
        [Parameter(Mandatory = $false)][array]$EscalationRisks = @(),
        [Parameter(Mandatory = $false)][hashtable]$GraphData = $null,
        [Parameter(Mandatory = $false)][hashtable]$GroupMemberships = @{},
        [Parameter(Mandatory = $false)][string]$OutputPath = "./ScEntra-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
    )

    Write-Verbose "Generating HTML report..."

    $stats = Get-ScEntraReportStatistics -Users $Users -Groups $Groups -ServicePrincipals $ServicePrincipals -AppRegistrations $AppRegistrations -RoleAssignments $RoleAssignments -PIMAssignments $PIMAssignments -EscalationRisks $EscalationRisks
    $roleDistribution = Get-ScEntraRoleDistribution -RoleAssignments $RoleAssignments
    $riskDistribution = Get-ScEntraRiskDistribution -EscalationRisks $EscalationRisks
    $generatedOn = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    $html = New-ScEntraReportDocument -Stats $stats -RoleDistribution $roleDistribution -RiskDistribution $riskDistribution -EscalationRisks $EscalationRisks -GraphData $GraphData -GeneratedOn $generatedOn

    try {
        $html | Out-File -FilePath $OutputPath -Encoding UTF8
        Write-Host "Report generated successfully: $OutputPath" -ForegroundColor Green

        $jsonPath = $OutputPath -replace '\.html$', '.json'
        $jsonData = @{
            GeneratedAt = Get-Date -Format 'o'
            Statistics = $stats
            Users = $Users | Select-Object id, displayName, userPrincipalName, accountEnabled, userType
            Groups = $Groups | Select-Object id, displayName, isAssignableToRole, isPIMEnabled, securityEnabled, memberCount
            ServicePrincipals = $ServicePrincipals | Select-Object id, displayName, appId, accountEnabled
            AppRegistrations = $AppRegistrations | Select-Object id, displayName, appId
            RoleAssignments = $RoleAssignments
            PIMAssignments = $PIMAssignments
            GroupMemberships = $GroupMemberships
            EscalationRisks = $EscalationRisks
            GraphData = $GraphData
        }

        $jsonData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
        Write-Host "JSON data exported to: $jsonPath" -ForegroundColor Green

        return $OutputPath
    }
    catch {
        Write-Error "Error generating report: $_"
        return $null
    }
}
