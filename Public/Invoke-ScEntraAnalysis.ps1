function Invoke-ScEntraAnalysis {
    <#
    .SYNOPSIS
        Main function to perform complete Entra ID security analysis

    .DESCRIPTION
        Orchestrates the complete analysis workflow:
        1. Connects to Microsoft Graph (if not already connected)
        2. Inventories all identity objects (users, groups, service principals, apps)
        3. Enumerates role assignments (direct and PIM)
        4. Analyzes escalation paths
        5. Generates HTML and JSON reports

    .PARAMETER OutputPath
        Path where to save the report (default: current directory)

    .PARAMETER SkipConnection
        Skip the connection check/prompt (assumes already connected)

    .EXAMPLE
        # First authenticate using Azure PowerShell or Azure CLI
        # Connect-AzAccount  # or: az login
        Invoke-ScEntraAnalysis

    .EXAMPLE
        Invoke-ScEntraAnalysis -OutputPath "C:\Reports\entra-report.html"

    .EXAMPLE
        # Use with an existing access token
        Connect-ScEntraGraph -AccessToken "eyJ0..."
        Invoke-ScEntraAnalysis -SkipConnection
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = "./ScEntra-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').html",

        [Parameter(Mandatory = $false)]
        [switch]$SkipConnection
    )

    Write-Host @"

╔═════════════════════════════════════════════════════════════════╗
║                                                                 ║
║   ███████╗ ██████╗███████╗███╗   ██╗████████╗██████╗ █████╗     ║
║   ██╔════╝██╔════╝██╔════╝████╗  ██║╚══██╔══╝██╔══██╗██╔══██╗   ║
║   ███████╗██║     █████╗  ██╔██╗ ██║   ██║   ██████╔╝███████║   ║
║   ╚════██║██║     ██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗██╔══██║   ║
║   ███████║╚██████╗███████╗██║ ╚████║   ██║   ██║  ██║██║  ██║   ║
║   ╚══════╝ ╚═════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝   ║
║                                                                 ║
║           Scan Entra for Risk & Escalation Paths                ║
║                                                                 ║
╚═════════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan

    if (-not $SkipConnection) {
        if ([string]::IsNullOrEmpty($script:GraphAccessToken)) {
            Write-Host "`nNot connected to Microsoft Graph." -ForegroundColor Yellow
            Write-Host "Connecting with required scopes..." -ForegroundColor Cyan

            $requiredScopes = @(
                "User.Read.All"
                "Group.Read.All"
                "Application.Read.All"
                "RoleManagement.Read.Directory"
                "RoleEligibilitySchedule.Read.Directory"
                "RoleAssignmentSchedule.Read.Directory",
                "PrivilegedAccess.Read.AzureADGroup"
            )

            $connected = Connect-ScEntraGraph -Scopes $requiredScopes
            if (-not $connected) {
                Write-Error "Failed to connect to Microsoft Graph. Please authenticate using Azure PowerShell (Connect-AzAccount) or Azure CLI (az login) first."
                return
            }
        }
        else {
            Write-Host "✓ Already connected to Microsoft Graph" -ForegroundColor Green
        }
    }

    $startTime = Get-Date

    Write-Host "[1/5] 📋 Collecting Inventory..." -ForegroundColor Cyan

    $inventory = Get-ScEntraUsersAndGroups
    $users = $inventory.Users
    $groups = $inventory.Groups
    $servicePrincipals = Get-ScEntraServicePrincipals
    $appRegistrations = Get-ScEntraAppRegistrations

    Write-Host "[2/5] 👑 Enumerating Role Assignments..." -ForegroundColor Cyan

    $roleAssignments = Get-ScEntraRoleAssignments
    Write-Host "[3/5] 🔐 Checking PIM Assignments..." -ForegroundColor Cyan

    $pimAssignments = Get-ScEntraPIMAssignments
    Write-Host "[4/5] 🔍 Analyzing Escalation Paths..." -ForegroundColor Cyan


    $escalationResult = Get-ScEntraEscalationPaths `
        -Users $users `
        -Groups $groups `
        -RoleAssignments $roleAssignments `
        -PIMAssignments $pimAssignments `
        -ServicePrincipals $servicePrincipals `
        -AppRegistrations $appRegistrations

    $escalationRisks = $escalationResult.Risks
    $graphData = $escalationResult.GraphData

    Write-Host "`n[5/5] 📊 Generating Report..." -ForegroundColor Cyan

    $reportPath = Export-ScEntraReport `
        -Users $users `
        -Groups $groups `
        -ServicePrincipals $servicePrincipals `
        -AppRegistrations $appRegistrations `
        -RoleAssignments $roleAssignments `
        -PIMAssignments $pimAssignments `
        -EscalationRisks $escalationRisks `
        -GraphData $graphData `
        -OutputPath $OutputPath

    $endTime = Get-Date
    $duration = $endTime - $startTime

    Write-Host "`n" + ("=" * 60) -ForegroundColor Green
    Write-Host "✓ Analysis Complete!" -ForegroundColor Green
    Write-Host ("=" * 60) -ForegroundColor Green
    Write-Host "`nSummary:"
    Write-Host "  • Users: $($users.Count)" -ForegroundColor White
    Write-Host "  • Groups: $($groups.Count)" -ForegroundColor White
    Write-Host "  • Service Principals: $($servicePrincipals.Count)" -ForegroundColor White
    Write-Host "  • App Registrations: $($appRegistrations.Count)" -ForegroundColor White
    Write-Host "  • Role Assignments: $($roleAssignments.Count)" -ForegroundColor White
    Write-Host "  • PIM Assignments: $($pimAssignments.Count)" -ForegroundColor White
    Write-Host "  • Escalation Risks: $($escalationRisks.Count)" -ForegroundColor Yellow
    
    # Show missing permissions summary if any were encountered
    $missingPermissions = Get-MissingPermissionsSummary
    if ($missingPermissions.Count -gt 0) {
        Write-Host "`n⚠️  Missing Permissions Detected:" -ForegroundColor Yellow
        foreach ($perm in $missingPermissions) {
            Write-Host "  • $perm" -ForegroundColor Yellow
        }
        Write-Host "`nTo resolve: Disconnect and reconnect with required permissions:" -ForegroundColor Cyan
        Write-Host "  Disconnect-AzAccount" -ForegroundColor Gray
        Write-Host "  Connect-AzAccount" -ForegroundColor Gray
        Write-Host "  Then grant the missing permissions when prompted." -ForegroundColor Gray
    }
    
    Write-Host "`nReport Location: $reportPath" -ForegroundColor Cyan
    Write-Host "Duration: $($duration.ToString('mm\:ss'))" -ForegroundColor Gray

    return @{
        Users             = $users
        Groups            = $groups
        ServicePrincipals = $servicePrincipals
        AppRegistrations  = $appRegistrations
        RoleAssignments   = $roleAssignments
        PIMAssignments    = $pimAssignments
        EscalationRisks   = $escalationRisks
        GraphData         = $graphData
        ReportPath        = $reportPath
    }
}
