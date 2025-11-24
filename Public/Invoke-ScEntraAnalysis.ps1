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

    .PARAMETER IncludeAllGroupNesting
        Include all group memberships and ownerships in the graph (default: only privileged groups)
        WARNING: This can significantly increase analysis time in large tenants

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

    .EXAMPLE
        # Include all group nesting relationships
        Invoke-ScEntraAnalysis -IncludeAllGroupNesting
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = "./ScEntra-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').html",

        [Parameter(Mandatory = $false)]
        [switch]$SkipConnection,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeAllGroupNesting
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

    $continue = $true
    # Initialize result variables outside the loop
    $users = @()
    $groups = @()
    $servicePrincipals = @()
    $appRegistrations = @()
    $roleAssignments = @()
    $pimAssignments = @()
    $escalationRisks = @()
    $graphData = $null
    $reportPath = $null

    do {
        Write-Host "`n📋 Available Functions:" -ForegroundColor Yellow
        Write-Host "  [1] Run Full Analysis" -ForegroundColor White
        Write-Host "  [2] Connect to Microsoft Graph" -ForegroundColor White
        Write-Host "  [3] Connect with Current Context" -ForegroundColor White
        Write-Host "  [4] Export Report (from existing JSON)" -ForegroundColor White
        Write-Host "  [5] Check Current Connection" -ForegroundColor White
        Write-Host "  [6] Toggle Full Group Nesting $(if ($IncludeAllGroupNesting) { '[ON]' } else { '[OFF]' })" -ForegroundColor White
        Write-Host "  [7] Exit" -ForegroundColor White
        Write-Host ""

        $choice = Read-Host "Select option (1-7)"

        switch ($choice) {
            "1" {
                Write-Host "`n▶ Starting Full Analysis..." -ForegroundColor Cyan
                Write-Host ""
                
                # Connection check
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
                            continue
                        }
                    }
                    else {
                        Write-Host "✓ Already connected to Microsoft Graph" -ForegroundColor Green
                    }
                }

                # Permission pre-check
                $mapCriticalPermissions = @(
                    'Group.Read.All'
                    'Application.Read.All'
                    'RoleManagement.Read.Directory'
                    'PrivilegedAccess.Read.AzureADGroup'
                )

                $tokenInfo = Get-GraphTokenScopeInfo
                if ($tokenInfo) {
                    $mapCoverage = Get-GraphPermissionCoverage -RequiredPermissions $mapCriticalPermissions -TokenInfo $tokenInfo
                    if ($mapCoverage -and -not $mapCoverage.HasAny) {
                        Write-Error "Cannot run Invoke-ScEntraAnalysis because none of the map-critical permissions are granted ($($mapCriticalPermissions -join ', ')). Reconnect with at least one of these scopes before retrying."
                        continue
                    }
                    elseif ($mapCoverage -and -not $mapCoverage.HasAll) {
                        $missingMapPermissions = $mapCoverage.MissingPermissions -join ', '
                        Write-Warning "Proceeding with limited map data. Missing permissions: $missingMapPermissions"
                    }
                }
                else {
                    Write-Verbose "Unable to decode token for permission pre-checks. Continuing without early gating."
                }

                $startTime = Get-Date

                Write-Host "[1/5] 📋 Collecting Inventory..." -ForegroundColor Cyan

                $inventory = Get-ScEntraUsersAndGroups
                $users = $inventory.Users
                $groups = $inventory.Groups

                $servicePrincipals = @()
                try {
                    $servicePrincipals = Get-ScEntraServicePrincipals
                }
                catch {
                    Write-Error "Failed to retrieve service principals: $($_.Exception.Message)"
                    $servicePrincipals = @()
                }

                $appRegistrations = @()
                try {
                    $appRegistrations = Get-ScEntraAppRegistrations
                }
                catch {
                    Write-Error "Failed to retrieve app registrations: $($_.Exception.Message)"
                    $appRegistrations = @()
                }

                Write-Host "[2/5] 👑 Enumerating Role Assignments..." -ForegroundColor Cyan

                $roleAssignments = @()
                try {
                    $roleAssignments = Get-ScEntraRoleAssignments
                }
                catch {
                    Write-Error "Failed to retrieve role assignments: $($_.Exception.Message)"
                    $roleAssignments = @()
                }
                Write-Host "[3/5] 🔐 Checking PIM Assignments..." -ForegroundColor Cyan

                $pimAssignments = @()
                try {
                    $pimAssignments = Get-ScEntraPIMAssignments
                }
                catch {
                    Write-Error "Failed to retrieve PIM assignments: $($_.Exception.Message)"
                    $pimAssignments = @()
                }

                $missingPermissions = Get-MissingPermissionsSummary

                if (-not $roleAssignments -or $roleAssignments.Count -eq 0) {
                    if ($missingPermissions -and ($missingPermissions -contains 'RoleManagement.Read.Directory')) {
                        Write-Error "Role assignments could not be collected because RoleManagement.Read.Directory is missing. Cannot analyze escalation paths without this dataset."
                        continue
                    }

                    Write-Warning "No role assignments were returned. Escalation map may be empty."
                }
                Write-Host "[4/5] 🔍 Analyzing Escalation Paths..." -ForegroundColor Cyan

                try {
                    $escalationResult = Get-ScEntraEscalationPaths `
                        -Users $users `
                        -Groups $groups `
                        -RoleAssignments $roleAssignments `
                        -PIMAssignments $pimAssignments `
                        -ServicePrincipals $servicePrincipals `
                        -AppRegistrations $appRegistrations
                }
                catch {
                    Write-Error "Failed to analyze escalation paths: $($_.Exception.Message)"
                    continue
                }

                if (-not $escalationResult) {
                    Write-Error "Escalation analysis returned no data. Unable to continue without graph insights."
                    continue
                }

                $escalationRisks = $escalationResult.Risks
                $graphData = $escalationResult.GraphData

                Write-Host "`n[5/5] 📊 Generating Report..." -ForegroundColor Cyan

                try {
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
                }
                catch {
                    Write-Error "Failed to generate the report output: $($_.Exception.Message)"
                    continue
                }

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

                Write-Host "`nPress any key to return to menu..." -ForegroundColor Gray
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                
                break
            }
            "2" {
                Write-Host "`n▶ Initiating Graph Connection..." -ForegroundColor Cyan
                $requiredScopes = @(
                    "User.Read.All"
                    "Group.Read.All"
                    "Application.Read.All"
                    "RoleManagement.Read.Directory"
                    "RoleEligibilitySchedule.Read.Directory"
                    "RoleAssignmentSchedule.Read.Directory"
                    "PrivilegedAccess.Read.AzureADGroup"
                )
                $connected = Connect-ScEntraGraph -Scopes $requiredScopes -UseDeviceCode
                if ($connected) {
                    Write-Host "✓ Successfully connected to Microsoft Graph" -ForegroundColor Green
                }
                continue
            }
            "3" {
                Write-Host "`n▶ Connecting with Current Context..." -ForegroundColor Cyan
                $connected = Connect-ScEntraGraph
                if ($connected) {
                    Write-Host "✓ Successfully connected to Microsoft Graph using current context" -ForegroundColor Green
                }
                continue
            }
            "4" {
                Write-Host "`n▶ Export Report from JSON..." -ForegroundColor Cyan
                $jsonPath = Read-Host "Enter path to JSON file"
                if (Test-Path $jsonPath) {
                    & "$PSScriptRoot\..\Generate-ReportFromJson.ps1" -JsonPath $jsonPath
                    Write-Host "✓ Report generated successfully" -ForegroundColor Green
                }
                else {
                    Write-Error "JSON file not found: $jsonPath"
                }
                continue
            }
            "5" {
                Write-Host "`n▶ Checking Connection Status..." -ForegroundColor Cyan
                if ([string]::IsNullOrEmpty($script:GraphAccessToken)) {
                    Write-Host "✗ Not connected to Microsoft Graph" -ForegroundColor Red
                    Write-Host "  Run option [2] or [3] to connect" -ForegroundColor Yellow
                }
                else {
                    Write-Host "✓ Connected to Microsoft Graph" -ForegroundColor Green
                    $tokenInfo = Get-GraphTokenScopeInfo
                    if ($tokenInfo) {
                        Write-Host "  Token Type: $(if ($tokenInfo.IsServicePrincipal) { 'Service Principal' } else { 'User' })" -ForegroundColor Gray
                        Write-Host "  Scopes: $($tokenInfo.Scopes -join ', ')" -ForegroundColor Gray
                    }
                }
                continue
            }
            "6" {
                $IncludeAllGroupNesting = -not $IncludeAllGroupNesting
                $status = if ($IncludeAllGroupNesting) { "ENABLED" } else { "DISABLED" }
                Write-Host "`n⚙️  Full Group Nesting: $status" -ForegroundColor Cyan
                if ($IncludeAllGroupNesting) {
                    Write-Host "  ⚠️  This will analyze ALL groups for memberships and owners (may take longer)" -ForegroundColor Yellow
                } else {
                    Write-Host "  ℹ️  Only privileged groups will be analyzed (faster, recommended)" -ForegroundColor Gray
                }
                continue
            }
            "7" {
                Write-Host "`nExiting ScEntra..." -ForegroundColor Gray
                $continue = $false
                return
            }
            default {
                Write-Host "`n✗ Invalid option. Please select 1-7." -ForegroundColor Yellow
                continue
            }
        }

    } while ($continue)

    # Return results if analysis was completed
    if ($reportPath) {
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
}
