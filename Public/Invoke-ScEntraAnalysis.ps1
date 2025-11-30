function Invoke-ScEntraAnalysis {
    <#
    .SYNOPSIS
        Main function to perform complete Entra ID security analysis

    .DESCRIPTION
        Provides an interactive menu for connecting to Microsoft Graph, running the full analysis
        workflow, exporting reports (including redacted variants), and inspecting connection status.

    .PARAMETER OutputPath
        Path where to save the generated HTML report (defaults to ./reports timestamped file).

    .PARAMETER SkipConnection
        Skips the initial connection prompt when you already have a valid Graph token loaded.

    .PARAMETER IncludeAllGroupNesting
        Reserved for future expansion to include all group nesting relationships in the graph.

    .PARAMETER EncryptReport
        When set, generates a self-decrypting HTML report that prompts for a password in the browser.

    .PARAMETER EncryptionPassword
        Optional password to use for encryption; if omitted you will be prompted.

    .PARAMETER EncryptedOutputPath
        Optional path for the encrypted HTML payload. Defaults to OutputPath.

    .PARAMETER DeletePlaintextAfterEncryption
        Legacy switch retained for compatibility. Encrypted reports are written directly so the
        switch has no effect.

    .PARAMETER AutoUnlock
        Embeds the supplied password so the encrypted HTML decrypts automatically on load while
        keeping the payload encrypted at rest.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$OutputPath,

        [Parameter(Mandatory = $false)]
        [switch]$SkipConnection,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeAllGroupNesting,

        [Parameter(Mandatory = $false)]
        [switch]$EncryptReport,

        [Parameter(Mandatory = $false)]
        [System.Security.SecureString]$EncryptionPassword,

        [Parameter(Mandatory = $false)]
        [string]$EncryptedOutputPath,

        [Parameter(Mandatory = $false)]
        [switch]$DeletePlaintextAfterEncryption,

        [Parameter(Mandatory = $false)]
        [switch]$AutoUnlock
    )

    if (-not $EncryptReport -and (
            $PSBoundParameters.ContainsKey('EncryptionPassword') -or 
            $PSBoundParameters.ContainsKey('EncryptedOutputPath') -or 
            $DeletePlaintextAfterEncryption)) {
        $EncryptReport = $true
    }

    if ($AutoUnlock -and -not $EncryptReport) {
        $EncryptReport = $true
    }

    function Show-ScEntraLogo {
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
    }

    function Get-AnalysisReportOptions {
        param(
            [string]$ContextDescription = "analysis"
        )

        Clear-Host
        Show-ScEntraLogo

        $options = @{}

        Write-Host "`n🔧 $ContextDescription Options:" -ForegroundColor Yellow
        Write-Host "  [1] Standard Analysis/Report" -ForegroundColor White
        Write-Host "  [2] Redacted Analysis/Report (removes PII)" -ForegroundColor White
        Write-Host "  [3] Encrypted Report (password protected)" -ForegroundColor White
        Write-Host "  [4] Redacted + Encrypted Report" -ForegroundColor White
        Write-Host "  [5] Back to Main Menu" -ForegroundColor White
        Write-Host ""

        $choice = Read-Host "Select option (1-5)"

        switch ($choice) {
            "1" {
                # Standard - no options
                return $options
            }
            "2" {
                $options['RedactPII'] = $true
                return $options
            }
            "3" {
                $encryptOptions = Get-ScEntraEncryptionOptions -ContextDescription $ContextDescription
                $options += $encryptOptions
                return $options
            }
            "4" {
                $options['RedactPII'] = $true
                $encryptOptions = Get-ScEntraEncryptionOptions -ContextDescription $ContextDescription
                $options += $encryptOptions
                return $options
            }
            "5" {
                Clear-Host
                Show-ScEntraLogo
                return $null  # Back to main menu
            }
            default {
                Write-Host "`n✗ Invalid option. Please select 1-5." -ForegroundColor Red
                Start-Sleep -Seconds 1
                return Get-AnalysisReportOptions -ContextDescription $ContextDescription
            }
        }
    }

    function Show-ReportMenu {
        do {
            Write-Host "`n📄 Report Options:" -ForegroundColor Yellow
            Write-Host "  [1] Export Report (from existing JSON)" -ForegroundColor White
            Write-Host "  [2] Export Redacted Report (from existing JSON)" -ForegroundColor White
            Write-Host "  [3] Run Full Analysis (Redacted)" -ForegroundColor White
            Write-Host "  [4] Back to Main Menu" -ForegroundColor White
            Write-Host ""

            $choice = Read-Host "Select option (1-4)"

            switch ($choice) {
                "1" {
                    Write-Host "`n▶ Exporting Report from JSON..." -ForegroundColor Cyan
                    $jsonPath = Read-Host "Enter path to JSON file"
                    if (Test-Path $jsonPath) {
                        & "$PSScriptRoot\..\Generate-ReportFromJson.ps1" -JsonPath $jsonPath
                    } else {
                        Write-Host "✗ File not found: $jsonPath" -ForegroundColor Red
                    }
                    Write-Host "`nPress any key to continue..." -ForegroundColor Gray
                    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                }
                "2" {
                    Write-Host "`n▶ Exporting Redacted Report from JSON..." -ForegroundColor Cyan
                    $jsonPath = Read-Host "Enter path to JSON file"
                    if (Test-Path $jsonPath) {
                        & "$PSScriptRoot\..\Generate-ReportFromJson.ps1" -JsonPath $jsonPath -RedactPII
                    } else {
                        Write-Host "✗ File not found: $jsonPath" -ForegroundColor Red
                    }
                    Write-Host "`nPress any key to continue..." -ForegroundColor Gray
                    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                }
                "3" {
                    Write-Host "`n▶ Starting Full Analysis with Redaction..." -ForegroundColor Cyan
                    $analysisOptions = @{
                        RedactPII = $true
                        OutputSuffix = '-redacted'
                    }
                    Invoke-ScEntraFullAnalysis @analysisOptions `
                        -EncryptReport:$EncryptReport `
                        -EncryptionPassword $EncryptionPassword `
                        -EncryptedOutputPath $EncryptedOutputPath `
                        -DeletePlaintextAfterEncryption:$DeletePlaintextAfterEncryption `
                        -AutoUnlock:$AutoUnlock
                    Write-Host "`nPress any key to continue..." -ForegroundColor Gray
                    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                }
                "4" {
                    return
                }
                default {
                    Write-Host "`n✗ Invalid option. Please select 1-4." -ForegroundColor Red
                    Write-Host "`nPress any key to continue..." -ForegroundColor Gray
                    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                }
            }
        } while ($true)
    }

    # Display logo initially
    Show-ScEntraLogo

    # Show connection status
    try {
        if ([string]::IsNullOrEmpty($script:GraphAccessToken)) {
            Write-Host "✗ Not connected to Microsoft Graph" -ForegroundColor Red
        }
        else {
            Write-Host "✓ Connected to Microsoft Graph" -ForegroundColor Green
            $tokenInfo = Get-GraphTokenScopeInfo
            if ($tokenInfo) {
                $accountType = if ($tokenInfo.IsServicePrincipal) { 'Service Principal' } else { 'User' }
                $account = $tokenInfo.Account
                Write-Host "  Account Type: $accountType" -ForegroundColor Gray
                Write-Host "  Account: $account" -ForegroundColor Gray
            }
        }
    } catch {
        Write-Host "✗ Not connected to Microsoft Graph" -ForegroundColor Red
    }

    # Create reports folder if it doesn't exist
    $reportsFolder = Join-Path (Get-Location) "reports"
    if (-not (Test-Path $reportsFolder)) {
        New-Item -ItemType Directory -Path $reportsFolder -Force | Out-Null
    }

    # Set default output path if not specified
    if (-not $OutputPath) {
        $OutputPath = Join-Path $reportsFolder "ScEntra-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
    }

    function Invoke-ScEntraFullAnalysis {
        param(
            [switch]$RedactPII,
            [string]$OutputSuffix = '',
            [switch]$SkipConnectionOverride,
            [switch]$EncryptReport,
            [System.Security.SecureString]$EncryptionPassword,
            [string]$EncryptedOutputPath,
            [switch]$DeletePlaintextAfterEncryption,
            [switch]$AutoUnlock
        )

        $analysisOutputPath = $OutputPath
        if ($OutputSuffix) {
            if ($analysisOutputPath -match '\.html$') {
                $analysisOutputPath = $analysisOutputPath -replace '\.html$', "$OutputSuffix.html"
            }
            else {
                $analysisOutputPath = "$analysisOutputPath$OutputSuffix"
            }
        }

        $effectiveSkipConnection = if ($PSBoundParameters.ContainsKey('SkipConnectionOverride')) { [bool]$SkipConnectionOverride } else { $SkipConnection }

        if (-not $effectiveSkipConnection) {
            if ([string]::IsNullOrEmpty($script:GraphAccessToken)) {
                Write-Host "`nNot connected to Microsoft Graph." -ForegroundColor Yellow
                Write-Host "Connecting with required scopes..." -ForegroundColor Cyan

                $requiredScopes = @(
                    "User.Read.All"
                    "Group.Read.All"
                    "Application.Read.All"
                    "RoleManagement.Read.Directory"
                    "RoleEligibilitySchedule.Read.Directory"
                    "RoleAssignmentSchedule.Read.Directory"
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
                return
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

        Write-Host "[1/5] 🔍 Determining Environment Size..." -ForegroundColor Cyan
        try {
            $envConfig = Get-ScEntraEnvironmentSize
            Write-Host "  Environment Profile: $($envConfig.Profile)" -ForegroundColor Green
            Write-Host "    Batch Throttle: $($envConfig.BatchThrottleLimit) | Delay: $($envConfig.DelayBetweenBatches)ms | Max Batch Size: $($envConfig.MaxBatchSize)" -ForegroundColor Gray
        }
        catch {
            Write-Warning "Could not determine environment size automatically: $_"
            Write-Warning "Falling back to conservative Enterprise configuration"
            $envConfig = Get-ScEntraEnvironmentConfig -UserCount 100000 -GroupCount 50000 -ServicePrincipalCount 50000 -AppRegistrationCount 100000
        }

        Write-Host "[2/5] Collecting Inventory..." -ForegroundColor Cyan

        $organizationInfo = Get-ScEntraOrganizationInfo
        if ($organizationInfo) {
            Write-Host "  ✓ Organization: $($organizationInfo.DisplayName)" -ForegroundColor Green
            if ($organizationInfo.VerifiedDomains) {
                Write-Host "    Primary Domain: $($organizationInfo.VerifiedDomains)" -ForegroundColor Gray
            }
            if ($organizationInfo.TenantId) {
                Write-Host "    Tenant ID: $($organizationInfo.TenantId)" -ForegroundColor Gray
            }
        }

        Write-Host "  Starting parallel inventory collection..." -ForegroundColor Yellow

        $parallelResults = 0..2 | ForEach-Object -Parallel {
            $index = $_
            $moduleRoot = Join-Path $using:PSScriptRoot '..'
            $privateFolder = Join-Path -Path $moduleRoot -ChildPath 'Private'
            Get-ChildItem -Path $privateFolder -Filter '*.ps1' -File | ForEach-Object { . $_.FullName }
            $script:GraphBaseUrl = $using:script:GraphBaseUrl
            $script:GraphAccessToken = $using:script:GraphAccessToken
            switch ($index) {
                0 {
                    try {
                        $inventory = Get-ScEntraUsersAndGroups
                        @{ Type = 'inventory'; Users = $inventory.Users; Groups = $inventory.Groups; Error = $null }
                    }
                    catch {
                        @{ Type = 'inventory'; Users = @(); Groups = @(); Error = $_.Exception.Message }
                    }
                }
                1 {
                    try {
                        $sps = Get-ScEntraServicePrincipals
                        @{ Type = 'sp'; ServicePrincipals = $sps; Error = $null }
                    }
                    catch {
                        @{ Type = 'sp'; ServicePrincipals = @(); Error = $_.Exception.Message }
                    }
                }
                2 {
                    try {
                        $apps = Get-ScEntraAppRegistrations
                        @{ Type = 'app'; AppRegistrations = $apps; Error = $null }
                    }
                    catch {
                        @{ Type = 'app'; AppRegistrations = @(); Error = $_.Exception.Message }
                    }
                }
            }
        } -ThrottleLimit 3

        $inventoryResult = $parallelResults | Where-Object { $_.Type -eq 'inventory' }
        $spResult = $parallelResults | Where-Object { $_.Type -eq 'sp' }
        $appResult = $parallelResults | Where-Object { $_.Type -eq 'app' }

        $users = $inventoryResult.Users
        $groups = $inventoryResult.Groups
        $servicePrincipals = $spResult.ServicePrincipals
        $appRegistrations = $appResult.AppRegistrations

        if ($inventoryResult.Error) {
            Write-Warning "Error retrieving users and groups: $($inventoryResult.Error)"
        }
        if ($spResult.Error) {
            Write-Error "Failed to retrieve service principals: $($spResult.Error)"
        }
        if ($appResult.Error) {
            Write-Error "Failed to retrieve app registrations: $($appResult.Error)"
        }

        Write-Host "[3/5] Enumerating Role Assignments..." -ForegroundColor Cyan
        try {
            $roleAssignments = Get-ScEntraRoleAssignments
        }
        catch {
            Write-Error "Failed to retrieve role assignments: $($_.Exception.Message)"
            $roleAssignments = @()
        }

        Write-Host "[3/5] Checking PIM Assignments..." -ForegroundColor Cyan
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
                return
            }

            Write-Warning "No role assignments were returned. Escalation map may be empty."
        }

        Write-Host "[4/5] Analyzing Escalation Paths..." -ForegroundColor Cyan
        try {
            $escalationResult = Get-ScEntraEscalationPaths `
                -Users $users `
                -Groups $groups `
                -RoleAssignments $roleAssignments `
                -PIMAssignments $pimAssignments `
                -ServicePrincipals $servicePrincipals `
                -AppRegistrations $appRegistrations `
                -BatchThrottleLimit $envConfig.BatchThrottleLimit `
                -DelayBetweenBatches $envConfig.DelayBetweenBatches `
                -MaxBatchSize $envConfig.MaxBatchSize `
                -UseParallelEscalation $envConfig.UseParallelEscalation `
                -EscalationThrottleLimit $envConfig.EscalationThrottleLimit `
                -CircuitBreakerThreshold $envConfig.CircuitBreakerThreshold
        }
        catch {
            Write-Error "Failed to analyze escalation paths: $($_.Exception.Message)"
            return
        }

        if (-not $escalationResult) {
            Write-Error "Escalation analysis returned no data. Unable to continue without graph insights."
            return
        }

        $escalationRisks = $escalationResult.Risks
        $graphData = $escalationResult.GraphData

        Write-Host "`n[5/5] Generating Report..." -ForegroundColor Cyan

        if ($RedactPII) {
            Write-Host "Redacting PII data..." -ForegroundColor Yellow
            $redacted = Invoke-ScEntraDataRedaction `
                -Users $users `
                -Groups $groups `
                -ServicePrincipals $servicePrincipals `
                -AppRegistrations $appRegistrations `
                -RoleAssignments $roleAssignments `
                -PIMAssignments $pimAssignments `
                -EscalationRisks $escalationRisks `
                -GraphData $graphData `
                -OrganizationInfo $organizationInfo

            if ($redacted.Users) { $users = $redacted.Users }
            if ($redacted.Groups) { $groups = $redacted.Groups }
            if ($redacted.ServicePrincipals) { $servicePrincipals = $redacted.ServicePrincipals }
            if ($redacted.AppRegistrations) { $appRegistrations = $redacted.AppRegistrations }
            if ($redacted.EscalationRisks) { $escalationRisks = $redacted.EscalationRisks }
            if ($redacted.GraphData) { $graphData = $redacted.GraphData }
            if ($redacted.OrganizationInfo) { $organizationInfo = $redacted.OrganizationInfo }
        }

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
                -OrganizationInfo $organizationInfo `
                -OutputPath $analysisOutputPath `
                -EncryptReport:$EncryptReport `
                -EncryptionPassword $EncryptionPassword `
                -AutoUnlock:$AutoUnlock `
                -EncryptedOutputPath $EncryptedOutputPath `
                -DeletePlaintextAfterEncryption:$DeletePlaintextAfterEncryption
        }
        catch {
            Write-Error "Failed to generate the report output: $($_.Exception.Message)"
            return
        }

        $endTime = Get-Date
        $duration = $endTime - $startTime

        foreach ($pair in @{
            'users' = $users
            'groups' = $groups
            'servicePrincipals' = $servicePrincipals
            'appRegistrations' = $appRegistrations
            'roleAssignments' = $roleAssignments
            'pimAssignments' = $pimAssignments
            'escalationRisks' = $escalationRisks
            'graphData' = $graphData
            'reportPath' = $reportPath
        }.GetEnumerator()) {
            Set-Variable -Scope 1 -Name $pair.Key -Value $pair.Value
        }

        Write-Host "`n" ("=" * 60) -ForegroundColor Green
        Write-Host " Analysis Complete!" -ForegroundColor Green
        Write-Host ("=" * 60) -ForegroundColor Green
        Write-Host "`nSummary:"
        Write-Host "  • Users: $($users.Count)" -ForegroundColor White
        Write-Host "  • Groups: $($groups.Count)" -ForegroundColor White
        Write-Host "  • Service Principals: $($servicePrincipals.Count)" -ForegroundColor White
        Write-Host "  • App Registrations: $($appRegistrations.Count)" -ForegroundColor White
        Write-Host "  • Role Assignments: $($roleAssignments.Count)" -ForegroundColor White
        Write-Host "  • PIM Assignments: $($pimAssignments.Count)" -ForegroundColor White
        Write-Host "  • Escalation Risks: $($escalationRisks.Count)" -ForegroundColor Yellow

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

        Write-Host "Report Location: $reportPath" -ForegroundColor Cyan
        Write-Host "Duration: $($duration.ToString('mm\:ss'))" -ForegroundColor Gray

        Write-Host "`nPress any key to return to menu..." -ForegroundColor Gray
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        Clear-Host
        Show-ScEntraLogo
    }

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

    # Display logo initially
    Show-ScEntraLogo

    # Show connection status
    try {
        $context = Get-MgContext
        if ($context) {
            $accountType = if ($context.AppName) { "Service Principal" } else { "User" }
            $account = if ($context.AppName) { $context.AppName } else { $context.Account }
            Write-Host "✓ Connected to Microsoft Graph as $accountType`: $account" -ForegroundColor Green
        } else {
            Write-Host "✗ Not connected to Microsoft Graph" -ForegroundColor Red
        }
    } catch {
        Write-Host "✗ Not connected to Microsoft Graph" -ForegroundColor Red
    }

    do {
        Write-Host "`n📋 Available Functions:" -ForegroundColor Yellow
        Write-Host "  [1] Run Full Analysis" -ForegroundColor White
        Write-Host "  [2] Connect to Microsoft Graph" -ForegroundColor White
        Write-Host "  [3] Connect with Current Context" -ForegroundColor White
        Write-Host "  [4] Generate Report from JSON" -ForegroundColor White
        Write-Host "  [5] Check Current Connection" -ForegroundColor White
        Write-Host "  [6] Open Latest Report" -ForegroundColor White
        Write-Host "  [7] Exit" -ForegroundColor White
        Write-Host ""

        $choice = Read-Host "Select option (1-7)"

        switch ($choice) {
            "1" {
                $options = Get-AnalysisReportOptions -ContextDescription "Full Analysis"
                if ($options -eq $null) { continue }
                Write-Host "`n▶ Starting Full Analysis..." -ForegroundColor Cyan
                Invoke-ScEntraFullAnalysis @options `
                    -EncryptReport:$EncryptReport `
                    -EncryptionPassword $EncryptionPassword `
                    -EncryptedOutputPath $EncryptedOutputPath `
                    -DeletePlaintextAfterEncryption:$DeletePlaintextAfterEncryption `
                    -AutoUnlock:$AutoUnlock
                continue
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
                Write-Host "`nPress any key to return to menu..." -ForegroundColor Gray
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                Clear-Host
                Show-ScEntraLogo
                continue
            }
            "3" {
                Write-Host "`n▶ Connecting with Current Context..." -ForegroundColor Cyan
                $connected = Connect-ScEntraGraph
                if ($connected) {
                    Write-Host "✓ Successfully connected to Microsoft Graph using current context" -ForegroundColor Green
                }
                Write-Host "`nPress any key to return to menu..." -ForegroundColor Gray
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                Clear-Host
                Show-ScEntraLogo
                continue
            }
            "4" {
                $options = Get-AnalysisReportOptions -ContextDescription "Report Generation"
                if ($options -eq $null) { continue }
                Write-Host "`n▶ Generating Report from JSON..." -ForegroundColor Cyan
                $jsonPath = Read-Host "Enter path to JSON file"
                if (Test-Path $jsonPath) {
                    $scriptBlock = {
                        param($jsonPath, $options)
                        & "$PSScriptRoot\..\Generate-ReportFromJson.ps1" -JsonPath $jsonPath @options
                    }
                    & $scriptBlock $jsonPath $options
                } else {
                    Write-Host "✗ File not found: $jsonPath" -ForegroundColor Red
                }
                Write-Host "`nPress any key to continue..." -ForegroundColor Gray
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                Clear-Host
                Show-ScEntraLogo
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
                Write-Host "`nPress any key to return to menu..." -ForegroundColor Gray
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                Clear-Host
                Show-ScEntraLogo
                continue
            }
            "6" {
                Write-Host "`n▶ Opening Latest Report..." -ForegroundColor Cyan
                
                # Find latest HTML report in reports folder
                $reportsFolder = Join-Path (Get-Location) "reports"
                if (Test-Path $reportsFolder) {
                    $latestReport = Get-ChildItem -Path $reportsFolder -Filter "ScEntra-Report-*.html" | 
                        Sort-Object LastWriteTime -Descending | 
                        Select-Object -First 1
                    
                    if ($latestReport) {
                        Write-Host "  Opening: $($latestReport.Name)" -ForegroundColor Green
                        Invoke-Item $latestReport.FullName
                    } else {
                        Write-Host "  ✗ No reports found in reports folder" -ForegroundColor Yellow
                        Write-Host "    Generate a report first using option [1]" -ForegroundColor Gray
                    }
                } else {
                    Write-Host "  ✗ Reports folder does not exist" -ForegroundColor Yellow
                    Write-Host "    Generate a report first using option [1]" -ForegroundColor Gray
                }
                Write-Host "`nPress any key to return to menu..." -ForegroundColor Gray
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                Clear-Host
                Show-ScEntraLogo
                continue
            }
            "7" {
                Write-Host "`nExiting ScEntra..." -ForegroundColor Gray
                $continue = $false
                return
            }
            default {
                Write-Host "`n✗ Invalid option. Please select 1-7." -ForegroundColor Yellow
                Start-Sleep -Seconds 1
                Clear-Host
                Show-ScEntraLogo
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
