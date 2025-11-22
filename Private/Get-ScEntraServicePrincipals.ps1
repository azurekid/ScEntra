function Get-ScEntraServicePrincipals {
    <#
    .SYNOPSIS
        Gets all service principals from Entra ID

    .DESCRIPTION
        Retrieves comprehensive information about all service principals

    .EXAMPLE
        $servicePrincipals = Get-ScEntraServicePrincipals
    #>
    [CmdletBinding()]
    param()

    if (-not (Test-GraphConnection)) { return @() }

    # Check required permissions
    $requiredPermissions = @(
        'Application.Read.All',
        'DelegatedPermissionGrant.Read.All'
    )
    if (-not (Test-GraphPermissions -RequiredPermissions $requiredPermissions -ResourceName "Service Principals")) {
        Write-Warning "Cannot retrieve service principals without required permissions."
        return @()
    }

    $select = "id,displayName,appId,servicePrincipalType,accountEnabled,createdDateTime,appOwnerOrganizationId,appRoles,oauth2PermissionScopes"
    $uri = "$script:GraphBaseUrl/servicePrincipals?`$top=999&`$select=$select"

    try {
        $servicePrincipals = Get-AllGraphItems -Uri $uri -ProgressActivity "Retrieving service principals from Entra ID"

        # Build lookups for permission resolution
        $servicePrincipalById = @{}
        foreach ($sp in $servicePrincipals) {
            $servicePrincipalById[$sp.id] = $sp
        }

        $appRoleAssignmentsByPrincipal = @{}
        $delegatedGrantsByClient = @{}

        $batchSpSize = 50
        $assignmentSelect = "id,principalId,principalDisplayName,principalType,resourceId,resourceDisplayName,appRoleId"
        $grantSelect = "id,clientId,resourceId,scope,consentType,principalId"

        $spCount = 0
        $totalSPs = [math]::Max(1, $servicePrincipals.Count)

        $collectPagedItems = {
            param($response)

            $items = @()
            if (-not $response) { return $items }
            if ($response.body -and $response.body.value) {
                $items += $response.body.value
            }

            $nextLink = if ($response.body) { $response.body.'@odata.nextLink' } else { $null }
            while ($nextLink) {
                try {
                    $nextResult = Invoke-GraphRequest -Uri $nextLink -Method GET -ErrorAction Stop
                    if ($nextResult.value) {
                        $items += $nextResult.value
                    }
                    $nextLink = $nextResult.'@odata.nextLink'
                }
                catch {
                    Write-Verbose "Failed to fetch additional page for batch response $($response.id): $_"
                    break
                }
            }

            return $items
        }

        for ($i = 0; $i -lt $servicePrincipals.Count; $i += $batchSpSize) {
            $endIndex = [Math]::Min($i + $batchSpSize - 1, $servicePrincipals.Count - 1)
            $spChunk = $servicePrincipals[$i..$endIndex]

            $batchRequests = @()
            foreach ($sp in $spChunk) {
                $batchRequests += @{
                    id     = "approles-$($sp.id)"
                    method = 'GET'
                    url    = "/servicePrincipals/$($sp.id)/appRoleAssignments?`$select=$assignmentSelect"
                }
                $batchRequests += @{
                    id     = "oauth2-$($sp.id)"
                    method = 'GET'
                    url    = "/servicePrincipals/$($sp.id)/oauth2PermissionGrants?`$select=$grantSelect"
                }
            }

            $batchResponses = @{}
            try {
                $batchResponses = Invoke-GraphBatchRequest -Requests $batchRequests
            }
            catch {
                Write-Warning "Batch retrieval for service principal permissions failed: $_"
                continue
            }

            foreach ($sp in $spChunk) {
                $spCount++
                $percentComplete = [math]::Round(($spCount / $totalSPs) * 100)
                Write-Progress -Activity "Collecting service principal permissions" -Status "Processed $spCount of $totalSPs service principals" -PercentComplete $percentComplete -Id 6

                # Application permissions (app roles)
                $appRoleAssignments = @()
                $appRoleResponseKey = "approles-$($sp.id)"
                if ($batchResponses.ContainsKey($appRoleResponseKey)) {
                    $appRoleResponse = $batchResponses[$appRoleResponseKey]
                    if ($appRoleResponse.status -eq 200) {
                        $appRoleAssignments = & $collectPagedItems $appRoleResponse
                    }
                    else {
                        Write-Verbose "App role assignment batch request for $($sp.displayName) failed with status $($appRoleResponse.status)"
                    }
                }

                if ($appRoleAssignments.Count -gt 0) {
                    foreach ($assignment in $appRoleAssignments) {
                        $principalId = if ($assignment.principalId) { $assignment.principalId } else { $sp.id }
                        if (-not $appRoleAssignmentsByPrincipal.ContainsKey($principalId)) {
                            $appRoleAssignmentsByPrincipal[$principalId] = @()
                        }

                        $resource = if ($assignment.resourceId -and $servicePrincipalById.ContainsKey($assignment.resourceId)) {
                            $servicePrincipalById[$assignment.resourceId]
                        } else { $null }
                        $roleDefinition = $null
                        if ($resource -and $resource.appRoles) {
                            $roleDefinition = $resource.appRoles | Where-Object { $_.id -eq $assignment.appRoleId } | Select-Object -First 1
                        }

                        $appRoleAssignmentsByPrincipal[$principalId] += [PSCustomObject]@{
                            AssignmentId        = $assignment.id
                            ResourceId          = $assignment.resourceId
                            ResourceDisplayName = if ($assignment.resourceDisplayName) { $assignment.resourceDisplayName } elseif ($resource) { $resource.displayName } else { $null }
                            AppRoleId           = $assignment.appRoleId
                            AppRoleDisplayName  = if ($roleDefinition) { $roleDefinition.displayName } else { $null }
                            AppRoleValue        = if ($roleDefinition) { $roleDefinition.value } else { $null }
                            AppRoleDescription  = if ($roleDefinition) { $roleDefinition.description } else { $null }
                            PrincipalDisplayName = if ($assignment.principalDisplayName) { $assignment.principalDisplayName } else { $sp.displayName }
                        }
                    }
                }

                # Delegated permissions (OAuth2 grants)
                $delegatedAssignments = @()
                $grantResponseKey = "oauth2-$($sp.id)"
                if ($batchResponses.ContainsKey($grantResponseKey)) {
                    $grantResponse = $batchResponses[$grantResponseKey]
                    if ($grantResponse.status -eq 200) {
                        $delegatedAssignments = & $collectPagedItems $grantResponse
                    }
                    else {
                        Write-Verbose "OAuth2 grant batch request for $($sp.displayName) failed with status $($grantResponse.status)"
                    }
                }

                if ($delegatedAssignments.Count -gt 0) {
                    foreach ($grant in $delegatedAssignments) {
                        $clientId = if ($grant.clientId) { $grant.clientId } else { $sp.id }
                        if (-not $delegatedGrantsByClient.ContainsKey($clientId)) {
                            $delegatedGrantsByClient[$clientId] = @()
                        }

                        $resource = if ($grant.resourceId -and $servicePrincipalById.ContainsKey($grant.resourceId)) {
                            $servicePrincipalById[$grant.resourceId]
                        } else { $null }

                        $scopeNames = if ($grant.scope) { ($grant.scope -split ' ' | Where-Object { $_ -ne '' }) } else { @() }
                        $resolvedScopes = @()
                        if ($resource -and $resource.oauth2PermissionScopes) {
                            foreach ($scopeName in $scopeNames) {
                                $scopeDefinition = $resource.oauth2PermissionScopes | Where-Object { $_.value -eq $scopeName } | Select-Object -First 1
                                $resolvedScopes += [PSCustomObject]@{
                                    ScopeId          = if ($scopeDefinition) { $scopeDefinition.id } else { $null }
                                    ScopeName        = $scopeName
                                    ScopeDisplayName = if ($scopeDefinition) { $scopeDefinition.adminConsentDisplayName } else { $null }
                                    ScopeDescription = if ($scopeDefinition) { $scopeDefinition.adminConsentDescription } else { $null }
                                }
                            }
                        }
                        else {
                            foreach ($scopeName in $scopeNames) {
                                $resolvedScopes += [PSCustomObject]@{
                                    ScopeId          = $null
                                    ScopeName        = $scopeName
                                    ScopeDisplayName = $null
                                    ScopeDescription = $null
                                }
                            }
                        }

                        if ($resolvedScopes.Count -eq 0 -and $grant.scope) {
                            $resolvedScopes = @([PSCustomObject]@{
                                    ScopeId          = $null
                                    ScopeName        = $grant.scope
                                    ScopeDisplayName = $grant.scope
                                    ScopeDescription = $null
                                })
                        }

                        $delegatedGrantsByClient[$clientId] += [PSCustomObject]@{
                            GrantId            = $grant.id
                            ResourceId         = $grant.resourceId
                            ResourceDisplayName = if ($resource) { $resource.displayName } else { $null }
                            ConsentType        = $grant.consentType
                            PrincipalId        = $grant.principalId
                            RawScope           = $grant.scope
                            ResolvedScopes     = $resolvedScopes
                        }
                    }
                }
            }
        }

        Write-Progress -Activity "Collecting service principal permissions" -Completed -Id 6

        foreach ($sp in $servicePrincipals) {
            $appPerms = if ($appRoleAssignmentsByPrincipal.ContainsKey($sp.id)) {
                $appRoleAssignmentsByPrincipal[$sp.id]
            }
            else {
                @()
            }

            $delegatedPerms = if ($delegatedGrantsByClient.ContainsKey($sp.id)) {
                $delegatedGrantsByClient[$sp.id]
            }
            else {
                @()
            }

            $sp | Add-Member -NotePropertyName 'GrantedApplicationPermissions' -NotePropertyValue $appPerms -Force
            $sp | Add-Member -NotePropertyName 'GrantedDelegatedPermissions' -NotePropertyValue $delegatedPerms -Force
        }

        Write-Host "Retrieved $($servicePrincipals.Count) service principals" -ForegroundColor Green
        return $servicePrincipals
    }
    catch {
        Write-Error "Error retrieving service principals: $_"
        return @()
    }
}
