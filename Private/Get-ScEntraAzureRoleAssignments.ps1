function Get-ScEntraAzureRoleAssignments {
    <#
    .SYNOPSIS
        Retrieves Azure RBAC active and PIM-eligible role assignments.

    .DESCRIPTION
        Queries every enabled subscription via direct ARM REST calls (same approach as
        Get-RoleAssignment in BlackCat) to collect all active role assignments and
        PIM-eligible role schedule instances.  Role names are resolved from an
        in-memory concurrent dictionary that is pre-populated with all role definitions
        for each subscription; custom/unknown role lookups fall back to a per-scope
        REST call.  Results are deduplicated and enriched with blast-radius context.

    .PARAMETER Users
        Optional user objects used for principal display-name enrichment.

    .PARAMETER Groups
        Optional group objects used for principal display-name enrichment.

    .PARAMETER ServicePrincipals
        Optional service principal objects used for principal display-name enrichment.

    .PARAMETER ThrottleLimit
        Maximum number of concurrent subscription threads. Default 10.

    .EXAMPLE
        $azureRbac = Get-ScEntraAzureRoleAssignments -Users $users -Groups $groups -ServicePrincipals $servicePrincipals
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [array]$Users = @(),

        [Parameter(Mandatory = $false)]
        [array]$Groups = @(),

        [Parameter(Mandatory = $false)]
        [array]$ServicePrincipals = @(),

        [Parameter(Mandatory = $false)]
        [int]$ThrottleLimit = 10
    )

    # -------------------------------------------------------------------------
    # Helper: acquire an ARM bearer token
    # -------------------------------------------------------------------------
    function Get-ScEntraAzureManagementToken {
        try {
            $cliToken = az account get-access-token --resource https://management.azure.com --output json 2>$null | ConvertFrom-Json
            if ($cliToken -and $cliToken.accessToken) { return $cliToken.accessToken }
        }
        catch { Write-Verbose "Azure CLI token retrieval failed: $_" }

        try {
            $azCtx = Get-AzContext -ErrorAction SilentlyContinue
            if ($azCtx) {
                $tok = Get-AzAccessToken -ResourceUrl 'https://management.azure.com' -ErrorAction SilentlyContinue
                if ($tok) { return ($tok.Token | ConvertFrom-SecureString -AsPlainText) }
            }
        }
        catch { Write-Verbose "Az PowerShell token retrieval failed: $_" }

        return $null
    }

    # -------------------------------------------------------------------------
    # Helper: blast-radius human summary
    # -------------------------------------------------------------------------
    function Get-BlastRadiusSummary {
        param([string]$Scope, [string]$RoleName, [hashtable]$SubNames = @{})

        if ([string]::IsNullOrWhiteSpace($Scope)) { return $null }

        if ($Scope -eq '/') {
            return 'Tenant-root assignment; applies across the entire tenant hierarchy.'
        }
        if ($Scope -match '^/providers/Microsoft\.Management/managementGroups/([^/]+)$') {
            return "Management-group '$($Matches[1])' assignment; inherited by all child subscriptions and resource groups."
        }
        if ($Scope -match '^/subscriptions/([^/]+)$') {
            $subId   = $Matches[1]
            $subName = if ($SubNames.ContainsKey($subId)) { $SubNames[$subId] } else { $subId }
            return "Subscription-scope assignment; applies to all resources within '$subName'."
        }
        if ($Scope -match '^/subscriptions/[^/]+/resourceGroups/([^/]+)$') {
            return "Resource-group '$($Matches[1])' scope assignment; applies to all resources within the resource group."
        }
        if ($Scope -match '^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/([^/]+/[^/]+)/([^/]+)') {
            return "Resource-scope assignment for $($Matches[2]) ($($Matches[1])); applies to this specific resource only."
        }
        return 'Resource-scope assignment; applies to this specific resource.'
    }

    # =========================================================================
    # MAIN
    # =========================================================================
    $result = @{
        RoleAssignments         = @()
        EligibleRoleAssignments = @()
        Error                   = $null
    }

    $accessToken = Get-ScEntraAzureManagementToken
    if ([string]::IsNullOrEmpty($accessToken)) {
        $result.Error = 'No Azure management token available. Authenticate with az login or Connect-AzAccount first.'
        return $result
    }

    # ------------------------------------------------------------------
    # 1. List all enabled subscriptions (same as BlackCat)
    # ------------------------------------------------------------------
    $subscriptionIds   = @()
    $subscriptionNames = @{}     # id → displayName
    try {
        $headers  = @{ Authorization = "Bearer $accessToken"; 'Content-Type' = 'application/json' }
        $subResp  = Invoke-RestMethod -Uri 'https://management.azure.com/subscriptions?api-version=2022-12-01' -Headers $headers -Method GET -ErrorAction Stop
        $enabledSubs = @($subResp.value | Where-Object { $_.state -eq 'Enabled' })
        $subscriptionIds = @($enabledSubs | Select-Object -ExpandProperty subscriptionId)
        foreach ($sub in $enabledSubs) {
            if ($sub.subscriptionId -and $sub.displayName) {
                $subscriptionNames[$sub.subscriptionId] = $sub.displayName
            }
        }
        $tenantId = if ($enabledSubs.Count -gt 0 -and $enabledSubs[0].tenantId) { $enabledSubs[0].tenantId } else { $null }
    }
    catch {
        $result.Error = "Failed to enumerate subscriptions: $($_.Exception.Message)"
        return $result
    }

    if ($subscriptionIds.Count -eq 0) {
        $result.Error = 'No enabled subscriptions found for the current Azure context.'
        return $result
    }

    Write-Host "  Found $($subscriptionIds.Count) enabled subscription(s) for Azure RBAC collection" -ForegroundColor Cyan

    # ------------------------------------------------------------------
    # 2. Build principal display-name lookup from passed objects
    # ------------------------------------------------------------------
    $principalLookup = @{}
    foreach ($u in $Users)             { if ($u.id) { $principalLookup[$u.id] = @{ Name = $u.displayName; Type = 'User'             } } }
    foreach ($g in $Groups)            { if ($g.id) { $principalLookup[$g.id] = @{ Name = $g.displayName; Type = 'Group'            } } }
    foreach ($s in $ServicePrincipals) { if ($s.id) { $principalLookup[$s.id] = @{ Name = $s.displayName; Type = 'ServicePrincipal' } } }

    # ------------------------------------------------------------------
    # 3. Pre-fetch all role definitions per subscription → shared cache
    #    Thread-safe concurrent dictionary (same pattern as BlackCat)
    # ------------------------------------------------------------------
    $roleNameCache = [System.Collections.Concurrent.ConcurrentDictionary[string,string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    Write-Host '  Pre-loading role definitions...' -ForegroundColor Cyan

    $subscriptionIds | ForEach-Object -Parallel {
        $subId   = $_
        $cache   = $using:roleNameCache
        $token   = $using:accessToken
        $hdrs    = @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' }

        $next = "https://management.azure.com/subscriptions/$subId/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01"
        while ($next) {
            try {
                $resp = Invoke-RestMethod -Uri $next -Headers $hdrs -Method GET -ErrorAction Stop
                foreach ($def in $resp.value) {
                    if ($def.name -and $def.properties.roleName) {
                        $null = $cache.TryAdd($def.name.ToLowerInvariant(), $def.properties.roleName)
                    }
                }
                $next = if ($resp.nextLink) { $resp.nextLink } else { $null }
            }
            catch { $next = $null }
        }
    } -ThrottleLimit $ThrottleLimit

    Write-Host "  Loaded $($roleNameCache.Count) role definition(s) into cache" -ForegroundColor Green

    # ------------------------------------------------------------------
    # 4. Collect active role assignments per subscription in parallel
    #    (direct ARM REST, same approach as BlackCat)
    # ------------------------------------------------------------------
    Write-Host '  Collecting active Azure role assignments...' -ForegroundColor Cyan

    $activeBag = [System.Collections.Concurrent.ConcurrentBag[PSCustomObject]]::new()

    $subscriptionIds | ForEach-Object -Parallel {
        $subId    = $_
        $bag      = $using:activeBag
        $cache    = $using:roleNameCache
        $lookup   = $using:principalLookup
        $token    = $using:accessToken
        $subNames = $using:subscriptionNames
        $hdrs     = @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' }
        $base     = 'https://management.azure.com'

        try {
            $assignments = [System.Collections.Generic.List[object]]::new()
            $next = "$base/subscriptions/$subId/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
            while ($next) {
                $resp = Invoke-RestMethod -Uri $next -Headers $hdrs -Method GET -ErrorAction Stop
                if ($resp.value) { $assignments.AddRange([object[]]$resp.value) }
                $next = if ($resp.nextLink) { $resp.nextLink } else { $null }
            }

            foreach ($ra in $assignments) {
                $props       = $ra.properties
                $principalId = [string]$props.principalId
                $scope       = [string]$props.scope
                $roleDefId   = [string]$props.roleDefinitionId

                # Extract GUID from the full role-definition path (same as BlackCat split logic)
                $roleGuid = $null
                if ($roleDefId -match '([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$') {
                    $roleGuid = $Matches[1].ToLowerInvariant()
                }

                # Resolve name from cache; on miss try the definitions API
                $roleName = $null
                if ($roleGuid) { $null = $cache.TryGetValue($roleGuid, [ref]$roleName) }
                if (-not $roleName -and $roleGuid) {
                    try {
                        $defUri  = "$base/subscriptions/$subId/providers/Microsoft.Authorization/roleDefinitions/$roleGuid?api-version=2022-04-01"
                        $defResp = Invoke-RestMethod -Uri $defUri -Headers $hdrs -Method GET -ErrorAction Stop
                        $roleName = $defResp.properties.roleName
                        if ($roleName) { $null = $cache.TryAdd($roleGuid, $roleName) }
                    }
                    catch { $roleName = 'Unknown Role' }
                }
                if (-not $roleName) { $roleName = 'Unknown Role' }

                $principalName = $null
                $principalType = [string]$props.principalType
                if ($principalId -and $lookup.ContainsKey($principalId)) {
                    $entry         = $lookup[$principalId]
                    $principalName = $entry.Name
                    if (-not $principalType -and $entry.Type) { $principalType = $entry.Type }
                }

                $bag.Add([PSCustomObject]@{
                    AssignmentId     = [string]$ra.id
                    SubscriptionId   = $subId
                    SubscriptionName = if ($subNames.ContainsKey($subId)) { $subNames[$subId] } else { $null }
                    Scope            = $scope
                    RoleDefinitionId = $roleGuid
                    RoleName         = $roleName
                    PrincipalId      = $principalId
                    PrincipalType    = $principalType
                    PrincipalName    = $principalName
                    Condition        = [string]$props.condition
                    IsCustom         = $false
                    AssignmentType   = 'AzureRBAC'
                    BlastRadiusSummary = $null   # filled after dedup below
                })
            }
        }
        catch {
            Write-Information "Error collecting active assignments for subscription '$subId': $($_.Exception.Message)" -InformationAction Continue
        }
    } -ThrottleLimit $ThrottleLimit

    # ------------------------------------------------------------------
    # 5. Collect PIM-eligible assignments per subscription in parallel
    # ------------------------------------------------------------------
    Write-Host '  Collecting PIM-eligible Azure role assignments...' -ForegroundColor Cyan

    $eligibleBag = [System.Collections.Concurrent.ConcurrentBag[PSCustomObject]]::new()

    $subscriptionIds | ForEach-Object -Parallel {
        $subId    = $_
        $bag      = $using:eligibleBag
        $cache    = $using:roleNameCache
        $lookup   = $using:principalLookup
        $token    = $using:accessToken
        $subNames = $using:subscriptionNames
        $hdrs     = @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' }
        $base     = 'https://management.azure.com'

        try {
            $instances = [System.Collections.Generic.List[object]]::new()
            $next = "$base/subscriptions/$subId/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=2020-10-01"
            while ($next) {
                try {
                    $resp = Invoke-RestMethod -Uri $next -Headers $hdrs -Method GET -ErrorAction Stop
                    if ($resp.value) { $instances.AddRange([object[]]$resp.value) }
                    $next = if ($resp.nextLink) { $resp.nextLink } else { $null }
                }
                catch {
                    # 403/404 means PIM not licensed or no permissions – skip silently
                    Write-Verbose "PIM query skipped for subscription $subId : $($_.Exception.Message)"
                    $next = $null
                }
            }

            foreach ($inst in $instances) {
                $props       = $inst.properties
                $principalId = [string]$props.principalId
                $scope       = [string]$props.scope
                $roleDefId   = [string]$props.roleDefinitionId

                $roleGuid = $null
                if ($roleDefId -match '([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$') {
                    $roleGuid = $Matches[1].ToLowerInvariant()
                }

                $roleName = $null
                if ($roleGuid) { $null = $cache.TryGetValue($roleGuid, [ref]$roleName) }

                # Prefer expandedProperties display name when available (same as BlackCat)
                $expanded = $props.expandedProperties
                if ($expanded -and $expanded.roleDefinition.displayName) {
                    $roleName = $expanded.roleDefinition.displayName
                }
                if (-not $roleName -and $roleGuid) {
                    try {
                        $defUri  = "$base/subscriptions/$subId/providers/Microsoft.Authorization/roleDefinitions/$roleGuid?api-version=2022-04-01"
                        $defResp = Invoke-RestMethod -Uri $defUri -Headers $hdrs -Method GET -ErrorAction Stop
                        $roleName = $defResp.properties.roleName
                        if ($roleName) { $null = $cache.TryAdd($roleGuid, $roleName) }
                    }
                    catch { $roleName = 'Unknown Role' }
                }
                if (-not $roleName) { $roleName = 'Unknown Role' }

                $principalName = $null
                $principalType = [string]$props.principalType
                if ($principalId -and $lookup.ContainsKey($principalId)) {
                    $entry         = $lookup[$principalId]
                    $principalName = $entry.Name
                    if (-not $principalType -and $entry.Type) { $principalType = $entry.Type }
                }
                if (-not $principalName -and $expanded -and $expanded.principal.displayName) {
                    $principalName = $expanded.principal.displayName
                }
                if (-not $principalType -and $expanded -and $expanded.principal.type) {
                    $principalType = $expanded.principal.type
                }

                $bag.Add([PSCustomObject]@{
                    ScheduleId       = [string]$inst.id
                    SubscriptionId   = $subId
                    SubscriptionName = if ($subNames.ContainsKey($subId)) { $subNames[$subId] } else { $null }
                    Scope            = $scope
                    RoleDefinitionId = $roleGuid
                    RoleName         = $roleName
                    PrincipalId      = $principalId
                    PrincipalType    = $principalType
                    PrincipalName    = $principalName
                    Status           = [string]$props.status
                    StartDateTime    = $props.startDateTime
                    EndDateTime      = $props.endDateTime
                    AssignmentType   = 'AzureEligible'
                    BlastRadiusSummary = $null   # filled after dedup below
                })
            }
        }
        catch {
            Write-Verbose "Error collecting PIM eligible for subscription '$subId': $($_.Exception.Message)"
        }
    } -ThrottleLimit $ThrottleLimit

    # ------------------------------------------------------------------
    # 6. Deduplicate and attach blast-radius summaries
    # ------------------------------------------------------------------
    $seenActive   = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $seenEligible = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $activeList   = [System.Collections.Generic.List[PSCustomObject]]::new()
    $eligibleList = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($ra in $activeBag) {
        $key = "$($ra.PrincipalId)|$($ra.RoleDefinitionId)|$($ra.Scope)".ToLowerInvariant()
        if ($seenActive.Add($key)) {
            $ra.BlastRadiusSummary = Get-BlastRadiusSummary -Scope $ra.Scope -RoleName $ra.RoleName -SubNames $subscriptionNames
            $activeList.Add($ra)
        }
    }

    foreach ($er in $eligibleBag) {
        $key = "$($er.PrincipalId)|$($er.RoleDefinitionId)|$($er.Scope)".ToLowerInvariant()
        if ($seenEligible.Add($key)) {
            $er.BlastRadiusSummary = Get-BlastRadiusSummary -Scope $er.Scope -RoleName $er.RoleName -SubNames $subscriptionNames
            $eligibleList.Add($er)
        }
    }

    $result.RoleAssignments         = $activeList.ToArray()
    $result.EligibleRoleAssignments = $eligibleList.ToArray()
    $result.SubscriptionNames       = $subscriptionNames

    # ------------------------------------------------------------------
    # 7. Enumerate management group hierarchy (one lightweight recursive API call)
    # ------------------------------------------------------------------
    $managementGroupHierarchy = [System.Collections.Generic.List[PSCustomObject]]::new()
    if ($tenantId) {
        function Expand-MgNode {
            param(
                $Node,
                [string]$ParentId,
                [System.Collections.Generic.List[PSCustomObject]]$HierarchyList,
                [hashtable]$NamesLookup
            )
            $id          = [string]$Node.id
            $displayName = if ($Node.properties -and $Node.properties.displayName)                                    { [string]$Node.properties.displayName }
                           elseif ($Node.PSObject.Properties.Name -contains 'displayName' -and $Node.displayName) { [string]$Node.displayName }
                           else                                                                                      { [string]$Node.name }
            $itemType    = if ([string]$Node.type -eq '/subscriptions') { 'subscription' } else { 'managementGroup' }

            $HierarchyList.Add([PSCustomObject]@{
                Id          = $id
                Name        = [string]$Node.name
                DisplayName = $displayName
                ParentId    = if ($ParentId) { $ParentId } else { $null }
                ItemType    = $itemType
            })

            # Store MG display names keyed by full ARM path for scope label lookup in New-ScEntraGraphData
            if ($itemType -eq 'managementGroup' -and $id -and $displayName) {
                $NamesLookup[$id] = $displayName
            }

            $children = if ($Node.properties -and $Node.properties.children)                                           { @($Node.properties.children) }
                        elseif ($Node.PSObject.Properties.Name -contains 'children' -and $Node.children) { @($Node.children) }
                        else                                                                               { @() }
            foreach ($child in $children) {
                Expand-MgNode -Node $child -ParentId $id -HierarchyList $HierarchyList -NamesLookup $NamesLookup
            }
        }

        Write-Host '  Enumerating management group hierarchy...' -ForegroundColor Cyan
        try {
            $mgUri  = 'https://management.azure.com/providers/Microsoft.Management/managementGroups/{0}?api-version=2020-05-01&$expand=children&$recurse=true' -f $tenantId
            $mgResp = Invoke-RestMethod -Uri $mgUri -Headers $headers -Method GET -ErrorAction Stop
            Expand-MgNode -Node $mgResp -ParentId '' -HierarchyList $managementGroupHierarchy -NamesLookup $subscriptionNames
            Write-Host "  Found $($managementGroupHierarchy.Count) item(s) in management group hierarchy" -ForegroundColor Green
        }
        catch {
            Write-Warning "Could not enumerate management group hierarchy (requires Management Group reader permission): $($_.Exception.Message)"
        }
    }
    $result.ManagementGroupHierarchy = $managementGroupHierarchy.ToArray()

    Write-Host "  Azure RBAC: $($result.RoleAssignments.Count) active, $($result.EligibleRoleAssignments.Count) eligible assignment(s)" -ForegroundColor Green

    return $result
}
