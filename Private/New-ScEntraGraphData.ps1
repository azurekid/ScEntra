function New-ScEntraGraphData {
    <#
    .SYNOPSIS
        Builds graph data structure for visualization of escalation paths
    
    .DESCRIPTION
        Creates nodes and edges representing the relationships between users, groups, 
        service principals, app registrations, and role assignments for graph visualization
    
    .PARAMETER Users
        Array of users
    
    .PARAMETER Groups
        Array of groups
    
    .PARAMETER ServicePrincipals
        Array of service principals
    
    .PARAMETER AppRegistrations
        Array of app registrations
    
    .PARAMETER RoleAssignments
        Array of role assignments (includes both direct and PIM)
    
    .PARAMETER PIMAssignments
        Array of PIM assignments
    
    .PARAMETER GroupMemberships
        Hashtable of group memberships (groupId -> array of member objects)
    
    .PARAMETER GroupOwners
        Hashtable of group owners (groupId -> array of owner objects)
    
    .PARAMETER SPOwners
        Hashtable of service principal owners (spId -> array of owner objects)
    
    .PARAMETER SPAppRoleAssignments
        Hashtable of service principal app role assignments (spId -> array of principal objects)
    
    .PARAMETER AppOwners
        Hashtable of app registration owners (appId -> array of owner objects)
    
    .EXAMPLE
        $graphData = New-ScEntraGraphData -Users $users -Groups $groups -RoleAssignments $roles
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Users,
        
        [Parameter(Mandatory = $true)]
        [array]$Groups,
        
        [Parameter(Mandatory = $false)]
        [array]$ServicePrincipals = @(),
        
        [Parameter(Mandatory = $false)]
        [array]$AppRegistrations = @(),
        
        [Parameter(Mandatory = $true)]
        [array]$RoleAssignments,
        
        [Parameter(Mandatory = $false)]
        [array]$PIMAssignments = @(),
        
        [Parameter(Mandatory = $false)]
        [hashtable]$GroupMemberships = @{},
        
        [Parameter(Mandatory = $false)]
        [hashtable]$GroupOwners = @{},
        
        [Parameter(Mandatory = $false)]
        [hashtable]$SPOwners = @{},
        
        [Parameter(Mandatory = $false)]
        [hashtable]$SPAppRoleAssignments = @{},
        
        [Parameter(Mandatory = $false)]
        [hashtable]$AppOwners = @{}
    )
    
    Write-Verbose "Building graph data structure..."

    $servicePrincipalsById = @{}
    $servicePrincipalsByAppId = @{}
    foreach ($sp in $ServicePrincipals) {
        if ($sp.id -and -not $servicePrincipalsById.ContainsKey($sp.id)) {
            $servicePrincipalsById[$sp.id] = $sp
        }
        if ($sp.appId -and -not $servicePrincipalsByAppId.ContainsKey($sp.appId)) {
            $servicePrincipalsByAppId[$sp.appId] = $sp
        }
    }

    $permissionEscalationTargets = @{
        'Application.ReadWrite.All' = @{
            Roles       = @('Application Administrator', 'Cloud Application Administrator')
            Severity    = 'High'
            Description = 'Full application CRUD enables creation of malicious service principals.'
        }
        'AppRoleAssignment.ReadWrite.All' = @{
            Roles       = @('Privileged Role Administrator')
            Severity    = 'High'
            Description = 'Can assign any app role, including privileged service principals.'
        }
        'RoleManagement.ReadWrite.Directory' = @{
            Roles       = @('Privileged Role Administrator')
            Severity    = 'High'
            Description = 'Can manage directory roles and activate privileged admins.'
        }
        'Directory.AccessAsUser.All' = @{
            Roles       = @('Global Administrator')
            Severity    = 'High'
            Description = 'Full delegated access to all APIs as any user grants total tenant control.'
        }
        'Directory.ReadWrite.All' = @{
            Roles       = @('Global Administrator')
            Severity    = 'High'
            Description = 'Write access to directory objects allows privilege escalation through owners.'
        }
        'PrivilegedAccess.ReadWrite.AzureAD' = @{
            Roles       = @('Privileged Role Administrator')
            Severity    = 'High'
            Description = 'Can administer PIM objects and activate privileged assignments.'
        }
        'Group.ReadWrite.All' = @{
            Roles       = @('User Administrator')
            Severity    = 'Medium'
            Description = 'Can modify role-assignable groups and pivot into privileged memberships.'
        }
        'User.ReadWrite.All' = @{
            Roles       = @('User Administrator')
            Severity    = 'Medium'
            Description = 'Can change privileged user credentials and MFA configurations.'
        }
    }

    $permissionIconSvg = @'
<svg id="uuid-431a759c-a29d-4678-89ee-5b1b2666f890" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 18 18"><defs><linearGradient id="uuid-10478e68-1009-47b7-9e5e-1dad26a11858" x1="9" y1="18" x2="9" y2="0" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#198ab3"/><stop offset="1" stop-color="#32bedd"/></linearGradient><linearGradient id="uuid-7623d8a9-ce5d-405d-98e0-ff8e832bdf61" x1="7.203" y1="11.089" x2="7.203" y2="3.888" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#6f4bb2"/><stop offset="1" stop-color="#c69aeb"/></linearGradient></defs><path d="m11.844,12.791c-.316-.081-.641-.073-.947.015l-1.295-2.124c-.04-.065-.124-.087-.19-.049l-.536.309c-.068.039-.091.128-.05.195l1.296,2.127c-.667.668-.737,1.797.01,2.551.12.121.259.223.41.302.276.143.568.213.857.213.463,0,.916-.18,1.273-.527.125-.121.23-.263.31-.417.302-.579.28-1.233-.037-1.769-.245-.413-.636-.707-1.102-.826Zm.424,1.965c-.06.232-.207.428-.414.55-.207.122-.449.156-.682.097-.278-.071-.503-.267-.614-.541-.141-.349-.041-.762.245-1.007.171-.147.379-.222.592-.222.075,0,.151.009.225.029.233.06.428.206.551.413h0c.122.207.157.448.097.681Zm3.555-9.443c-1.012,0-1.863.695-2.106,1.631h-2.54c-.078,0-.141.063-.141.141v.806c0,.078.063.141.141.141h2.54c.243.937,1.093,1.631,2.106,1.631,1.201,0,2.177-.976,2.177-2.175s-.977-2.175-2.177-2.175Zm1.068,2.388c-.082.428-.427.772-.854.854-.766.146-1.428-.515-1.282-1.28.082-.428.426-.772.854-.854.766-.147,1.429.515,1.283,1.28ZM2.978,2.953c.121.03.244.045.366.045.144,0,.286-.022.423-.063l.884,1.447c.04.065.124.087.19.049l.406-.234c.068-.039.091-.128.05-.195l-.887-1.453c.468-.475.577-1.224.218-1.821-.206-.343-.534-.585-.923-.682-.445-.111-.909-.016-1.28.267-.547.417-.737,1.18-.45,1.805.195.424.559.725,1.004.835Zm-.083-2.056c.133-.097.288-.148.445-.148.061,0,.122.008.183.023.232.058.42.219.514.446.13.315.02.691-.258.889-.182.13-.405.172-.619.118-.232-.058-.42-.219-.514-.446-.129-.312-.023-.683.249-.883Zm2.717,10.093l-.828-.477c-.067-.039-.154-.016-.192.052l-1.473,2.577c-1.227-.327-2.587.325-3.009,1.668-.091.289-.125.595-.1.897.071.849.537,1.569,1.253,1.973.377.212.793.321,1.214.321.374,0,.752-.086,1.109-.259.289-.14.549-.34.758-.583.56-.652.743-1.497.522-2.293-.12-.432-.352-.813-.668-1.116l1.468-2.567c.038-.067.015-.153-.052-.192Zm-2.055,5.145l-.213.234c-.161.177-.367.315-.601.366-.298.065-.605.02-.873-.131-.288-.162-.495-.427-.584-.745-.089-.318-.048-.652.115-.939.227-.402.648-.628,1.08-.628.206,0,.415.051.606.16.288.162.495.427.584.745.089.318.048.652-.115.939Z" fill="url(#uuid-10478e68-1009-47b7-9e5e-1dad26a11858)"/><path d="m9.921,5.287l-2.172-1.253c-.339-.195-.757-.195-1.096,0l-2.172,1.253c-.339.196-.548.557-.548.948v2.505c0,.391.209.753.548.949l2.174,1.253c.339.195.757.195,1.096,0l2.174-1.253c.339-.196.548-.557.548-.949v-2.505c-.001-.392-.212-.754-.552-.948Z" fill="url(#uuid-7623d8a9-ce5d-405d-98e0-ff8e832bdf61)"/></svg>
'@

    $graphPermissionMapping = @{}
    $graphPermissionMappingPath = Join-Path -Path $PSScriptRoot -ChildPath 'graph-permissions.csv'
    if (Test-Path -Path $graphPermissionMappingPath) {
        try {
            $mappingEntries = Import-Csv -Path $graphPermissionMappingPath
            foreach ($entry in $mappingEntries) {
                if (-not $entry.PermissionId) { continue }
                $key = $entry.PermissionId.ToLower()
                $graphPermissionMapping[$key] = $entry
            }
            Write-Verbose "Loaded $($graphPermissionMapping.Count) API permission mappings from graph-permissions.csv"
        }
        catch {
            Write-Verbose "Failed to load API permission mapping file: $_"
        }
    }
    else {
        Write-Verbose "API permission mapping file not found at $graphPermissionMappingPath"
    }

    $resolvePermissionMetadata = {
        param(
            [string]$PermissionId
        )

        if (-not $PermissionId) { return $null }
        $key = $PermissionId.ToLower()
        if ($graphPermissionMapping.ContainsKey($key)) {
            return $graphPermissionMapping[$key]
        }
        return $null
    }

    $normalizeResourceName = {
        param(
            [string]$ResourceName,
            [string]$ResourceAppId
        )

        $legacyAppId = '00000002-0000-0000-c000-000000000000'
        if (($ResourceAppId -and $ResourceAppId -eq $legacyAppId) -or ($ResourceName -and $ResourceName -eq 'Windows Azure Active Directory')) {
            return 'Azure AD Graph (Legacy)'
        }
        return $ResourceName
    }

    $buildPermissionNodeId = {
        param(
            [string]$ResourceKey,
            [string]$Identifier,
            [string]$PermissionValue
        )
        if (-not $ResourceKey) { $ResourceKey = 'unknown' }
        $baseIdentifier = if ($PermissionValue) {
            $PermissionValue
        }
        elseif ($Identifier) {
            $Identifier
        }
        else {
            [Guid]::NewGuid().ToString('N')
        }
        $safeIdentifier = $baseIdentifier -replace '[^A-Za-z0-9]', '_'
        return "permission-$ResourceKey-$safeIdentifier"
    }

    $permissionAssociationTracker = [System.Collections.Generic.HashSet[string]]::new()
    $permissionEscalationEdgeTracker = [System.Collections.Generic.HashSet[string]]::new()

    $ensurePermissionNode = {
        param(
            [string]$NodeId,
            [string]$Label,
            [string]$ResourceName,
            [string]$PermissionValue,
            [string]$PermissionKind,
            [string]$PermissionDisplayName,
            [string]$PermissionDescription,
            [string]$PermissionAudience,
            [string]$AdminConsentRequired
        )

        if (-not $nodeIndex.ContainsKey($NodeId)) {
            $severity = 'Informational'
            $description = $null
            if ($PermissionValue -and $permissionEscalationTargets.ContainsKey($PermissionValue)) {
                $severity = $permissionEscalationTargets[$PermissionValue].Severity
                $description = $permissionEscalationTargets[$PermissionValue].Description
            }

            $grantTypes = @()
            if ($PermissionKind) { $grantTypes += $PermissionKind }
            $resolvedKind = if ($grantTypes.Count -eq 1) { $grantTypes[0] } elseif ($grantTypes.Count -gt 1) { 'Mixed' } else { $null }

            $null = $nodes.Add(@{
                id = $NodeId
                label = $Label
                type = 'apiPermission'
                resource = $ResourceName
                permissionValue = $PermissionValue
                permissionKind = $resolvedKind
                permissionDisplayName = $PermissionDisplayName
                permissionDescription = $PermissionDescription
                permissionAudience = $PermissionAudience
                adminConsentRequired = $AdminConsentRequired
                severity = $severity
                escalationDescription = $description
                iconSvg = $permissionIconSvg
                grantTypes = $grantTypes
            })
            $nodeIndex[$NodeId] = $nodes.Count - 1
        }
        else {
            $existingIndex = $nodeIndex[$NodeId]
            $existingNode = $nodes[$existingIndex]
            if ($PermissionKind) {
                if (-not $existingNode.ContainsKey('grantTypes') -or -not $existingNode.grantTypes) {
                    $existingNode.grantTypes = @()
                }
                if ($existingNode.grantTypes -notcontains $PermissionKind) {
                    $existingNode.grantTypes += $PermissionKind
                }
                if ($existingNode.grantTypes.Count -gt 1) {
                    $existingNode.permissionKind = 'Mixed'
                }
                else {
                    $existingNode.permissionKind = $existingNode.grantTypes[0]
                }
            }
            if (-not $existingNode.permissionDisplayName -and $PermissionDisplayName) {
                $existingNode.permissionDisplayName = $PermissionDisplayName
            }
            if (-not $existingNode.permissionDescription -and $PermissionDescription) {
                $existingNode.permissionDescription = $PermissionDescription
            }
            if (-not $existingNode.permissionAudience -and $PermissionAudience) {
                $existingNode.permissionAudience = $PermissionAudience
            }
            if (-not $existingNode.adminConsentRequired -and $AdminConsentRequired) {
                $existingNode.adminConsentRequired = $AdminConsentRequired
            }
        }
    }

    $linkPermissionToRoles = {
        param(
            [string]$NodeId,
            [string]$PermissionValue
        )

        if (-not $PermissionValue) { return }
        if (-not $permissionEscalationTargets.ContainsKey($PermissionValue)) { return }

        $mapping = $permissionEscalationTargets[$PermissionValue]
        foreach ($roleName in $mapping.Roles) {
            $roleNodeId = "role-$roleName"
            if (-not $nodeIndex.ContainsKey($roleNodeId)) {
                $isHighPrivilege = $highPrivilegeRoles -contains $roleName
                $null = $nodes.Add(@{
                    id = $roleNodeId
                    label = $roleName
                    type = 'role'
                    isPrivileged = $true
                    isHighPrivilege = $isHighPrivilege
                })
                $nodeIndex[$roleNodeId] = $nodes.Count - 1
            }

            $edgeKey = "perm-escalation::$NodeId->$roleNodeId"
            if (-not $permissionEscalationEdgeTracker.Contains($edgeKey)) {
                $null = $edges.Add(@{
                    from = $NodeId
                    to = $roleNodeId
                    type = 'escalates_to'
                    label = 'Enables Privilege'
                    description = $mapping.Description
                })
                [void]$permissionEscalationEdgeTracker.Add($edgeKey)
            }
        }
    }

    $nodes = [System.Collections.ArrayList]::new()
    $edges = [System.Collections.ArrayList]::new()
    $nodeIndex = @{}
    $resolveGroupShape = {
        param($group)
        if (-not $group) {
            return 'box'
        }

        if (($group.PSObject.Properties.Name -contains 'isPIMEnabled') -and $group.isPIMEnabled) {
            return 'diamond'
        }
        elseif ($group.securityEnabled) {
            return 'triangle'
        }

        return 'box'
    }

    $ensureUserNode = {
        param($user)

        if (-not $user -or -not $user.id) {
            return
        }

        $displayLabel = if ([string]::IsNullOrWhiteSpace($user.displayName)) {
            $user.userPrincipalName
        }
        else {
            $user.displayName
        }

        $baseNodeData = [ordered]@{
            id = $user.id
            label = $displayLabel
            type = 'user'
            userPrincipalName = $user.userPrincipalName
            accountEnabled = $user.accountEnabled
            mail = $user.mail
            userType = $user.userType
            onPremisesSyncEnabled = $user.onPremisesSyncEnabled
            createdDateTime = $user.createdDateTime
            lastPasswordChangeDateTime = $user.lastPasswordChangeDateTime
        }

        if ($user.PSObject.Properties.Name -contains 'signInSessionsValidFromDateTime') {
            $baseNodeData['signInSessionsValidFromDateTime'] = $user.signInSessionsValidFromDateTime
        }

        if (-not $nodeIndex.ContainsKey($user.id)) {
            $null = $nodes.Add($baseNodeData)
            $nodeIndex[$user.id] = $nodes.Count - 1
        }
        else {
            $existingNode = $nodes[$nodeIndex[$user.id]]
            foreach ($key in $baseNodeData.Keys) {
                $existingNode[$key] = $baseNodeData[$key]
            }
        }
    }
    
    # Define high-privilege roles for escalation path analysis
    $highPrivilegeRoles = @(
        'Global Administrator',
        'Privileged Role Administrator',
        'Security Administrator',
        'Cloud Application Administrator',
        'Application Administrator',
        'User Administrator',
        'Exchange Administrator',
        'SharePoint Administrator',
        'Global Reader',
        'Security Reader'
    )
    
    # Add role nodes (only for roles that have assignments)
    $assignedRoles = @($RoleAssignments | Select-Object -ExpandProperty RoleName -Unique)
    $pimRoles = @($PIMAssignments | Select-Object -ExpandProperty RoleName -Unique)
    $allRoles = @($assignedRoles; $pimRoles) | Select-Object -Unique

    $roleMetadataByName = @{}
    $collectRoleMetadata = {
        param($entry)

        if (-not $entry) { return }
        $roleName = $entry.RoleName
        if (-not $roleName) { return }

        if (-not $roleMetadataByName.ContainsKey($roleName)) {
            $metadata = @{
                Description         = $entry.RoleDescription
                TemplateId          = $entry.RoleTemplateId
                DefinitionId        = $entry.RoleDefinitionId
                IsBuiltIn           = $entry.RoleIsBuiltIn
                IsEnabled           = $entry.RoleIsEnabled
                ResourceScopes      = @()
                AllowedActions      = @()
                AllowedActionsCount = if ($entry.RoleAllowedActionsCount -ne $null) { [int]$entry.RoleAllowedActionsCount } else { $null }
            }

            if ($entry.RoleResourceScopes) {
                $metadata.ResourceScopes = @($entry.RoleResourceScopes | Sort-Object -Unique)
            }

            if ($entry.RoleAllowedActions) {
                $metadata.AllowedActions = @($entry.RoleAllowedActions | Sort-Object -Unique)
                if (-not $metadata.AllowedActionsCount) {
                    $metadata.AllowedActionsCount = $metadata.AllowedActions.Count
                }
            }

            $roleMetadataByName[$roleName] = $metadata
        }
        else {
            $metadata = $roleMetadataByName[$roleName]

            if (-not $metadata.Description -and $entry.RoleDescription) {
                $metadata.Description = $entry.RoleDescription
            }
            if (-not $metadata.TemplateId -and $entry.RoleTemplateId) {
                $metadata.TemplateId = $entry.RoleTemplateId
            }
            if (-not $metadata.DefinitionId -and $entry.RoleDefinitionId) {
                $metadata.DefinitionId = $entry.RoleDefinitionId
            }
            if ($metadata.IsBuiltIn -eq $null -and $entry.RoleIsBuiltIn -ne $null) {
                $metadata.IsBuiltIn = [bool]$entry.RoleIsBuiltIn
            }
            if ($metadata.IsEnabled -eq $null -and $entry.RoleIsEnabled -ne $null) {
                $metadata.IsEnabled = [bool]$entry.RoleIsEnabled
            }

            if ($entry.RoleResourceScopes) {
                $combinedScopes = @($metadata.ResourceScopes + $entry.RoleResourceScopes)
                if ($combinedScopes.Count -gt 0) {
                    $metadata.ResourceScopes = $combinedScopes | Sort-Object -Unique
                }
            }

            if ($entry.RoleAllowedActions) {
                $combinedActions = @($metadata.AllowedActions + $entry.RoleAllowedActions)
                if ($combinedActions.Count -gt 0) {
                    $metadata.AllowedActions = $combinedActions | Sort-Object -Unique
                }
            }

            if ($entry.RoleAllowedActionsCount -ne $null) {
                $metadata.AllowedActionsCount = [int]$entry.RoleAllowedActionsCount
            }
            elseif ($metadata.AllowedActions -and $metadata.AllowedActions.Count -gt 0) {
                $metadata.AllowedActionsCount = $metadata.AllowedActions.Count
            }
        }
    }

    foreach ($assignment in $RoleAssignments) { & $collectRoleMetadata $assignment }
    foreach ($assignment in $PIMAssignments) { & $collectRoleMetadata $assignment }
    
    foreach ($roleName in $allRoles) {
        $roleId = "role-$roleName"
        if (-not $nodeIndex.ContainsKey($roleId)) {
            $isHighPrivilege = $highPrivilegeRoles -contains $roleName
            $nodeData = @{
                id = $roleId
                label = $roleName
                type = 'role'
                isPrivileged = $true
                isHighPrivilege = $isHighPrivilege
            }

            if ($roleMetadataByName.ContainsKey($roleName)) {
                $metadata = $roleMetadataByName[$roleName]
                if ($metadata.Description) {
                    $nodeData.description = $metadata.Description
                }
                if ($metadata.TemplateId) {
                    $nodeData.roleTemplateId = $metadata.TemplateId
                }
                if ($metadata.DefinitionId) {
                    $nodeData.roleDefinitionId = $metadata.DefinitionId
                }
                if ($metadata.IsBuiltIn -ne $null) {
                    $nodeData.roleIsBuiltIn = [bool]$metadata.IsBuiltIn
                }
                if ($metadata.IsEnabled -ne $null) {
                    $nodeData.roleIsEnabled = [bool]$metadata.IsEnabled
                }
                if ($metadata.ResourceScopes -and $metadata.ResourceScopes.Count -gt 0) {
                    $nodeData.roleResourceScopes = @($metadata.ResourceScopes)
                }
                if ($metadata.AllowedActions -and $metadata.AllowedActions.Count -gt 0) {
                    $nodeData.roleAllowedActions = @($metadata.AllowedActions)
                    $nodeData.roleAllowedActionsCount = if ($metadata.AllowedActionsCount -ne $null) { [int]$metadata.AllowedActionsCount } else { $metadata.AllowedActions.Count }
                }
                elseif ($metadata.AllowedActionsCount -ne $null) {
                    $nodeData.roleAllowedActionsCount = [int]$metadata.AllowedActionsCount
                }
            }

            $null = $nodes.Add($nodeData)
            $nodeIndex[$roleId] = $nodes.Count - 1
        }
    }
    
    # Build a quick lookup of principals that currently have an active PIM assignment
    $activePIMAssignmentMap = @{}
    foreach ($pimAssignment in ($PIMAssignments | Where-Object { $_.AssignmentType -eq 'PIM-Active' })) {
        if ($pimAssignment.PrincipalId -and $pimAssignment.RoleId) {
            $key = "$($pimAssignment.PrincipalId)|$($pimAssignment.RoleId)"
            $activePIMAssignmentMap[$key] = $true
        }
    }

    # Add nodes and edges for direct role assignments
    foreach ($assignment in $RoleAssignments) {
        $assignmentKey = if ($assignment.MemberId -and $assignment.RoleId) { "$($assignment.MemberId)|$($assignment.RoleId)" } else { $null }

        # Skip direct connections that represent an active PIM assignment to avoid duplicate labels
        if ($assignmentKey -and $activePIMAssignmentMap.ContainsKey($assignmentKey)) {
            continue
        }

        $roleId = "role-$($assignment.RoleName)"
        
        # Determine the principal type and add node
        switch ($assignment.MemberType) {
            'user' {
                $user = $Users | Where-Object { $_.id -eq $assignment.MemberId } | Select-Object -First 1
                if ($user) {
                    & $ensureUserNode $user
                    $null = $edges.Add(@{
                        from = $user.id
                        to = $roleId
                        type = 'has_role'
                        label = 'Direct'
                    })
                }
            }
            'group' {
                $group = $Groups | Where-Object { $_.id -eq $assignment.MemberId } | Select-Object -First 1
                    if ($group) {
                    if (-not $nodeIndex.ContainsKey($group.id)) {
                        $groupShape = & $resolveGroupShape $group
                        $null = $nodes.Add(@{
                            id = $group.id
                            label = $group.displayName
                            type = 'group'
                            shape = $groupShape
                            isPIMEnabled = [bool]$group.isPIMEnabled
                            isAssignableToRole = $group.isAssignableToRole
                            securityEnabled = $group.securityEnabled
                        })
                        $nodeIndex[$group.id] = $nodes.Count - 1
                    }
                    $null = $edges.Add(@{
                        from = $group.id
                        to = $roleId
                        type = 'has_role'
                        label = 'Direct'
                    })
                }
            }
            'servicePrincipal' {
                $sp = $ServicePrincipals | Where-Object { $_.id -eq $assignment.MemberId } | Select-Object -First 1
                if ($sp) {
                    if (-not $nodeIndex.ContainsKey($sp.id)) {
                        $null = $nodes.Add(@{
                            id = $sp.id
                            label = $sp.displayName
                            type = 'servicePrincipal'
                            appId = $sp.appId
                            accountEnabled = $sp.accountEnabled
                        })
                        $nodeIndex[$sp.id] = $nodes.Count - 1
                    }
                    $null = $edges.Add(@{
                        from = $sp.id
                        to = $roleId
                        type = 'has_role'
                        label = 'Direct'
                    })
                }
            }
        }
    }
    
    # Add nodes and edges for PIM assignments (eligible)
    Write-Verbose "Processing $($PIMAssignments.Count) PIM assignments..."
    foreach ($pimAssignment in $PIMAssignments) {
        $roleId = "role-$($pimAssignment.RoleName)"
        $assignmentLabel = if ($pimAssignment.AssignmentType -eq 'PIM-Eligible') { 'Eligible' } else { 'PIM Active' }
        Write-Verbose "  PIM: $($pimAssignment.PrincipalType) $($pimAssignment.PrincipalId) -> $($pimAssignment.RoleName)"
        
        # Determine the principal type and add node
        switch ($pimAssignment.PrincipalType) {
            'user' {
                $user = $Users | Where-Object { $_.id -eq $pimAssignment.PrincipalId } | Select-Object -First 1
                if ($user) {
                    & $ensureUserNode $user
                    $null = $edges.Add(@{
                        from = $user.id
                        to = $roleId
                        type = 'has_role'
                        label = $assignmentLabel
                        isPIM = $true
                    })
                }
            }
            'group' {
                $group = $Groups | Where-Object { $_.id -eq $pimAssignment.PrincipalId } | Select-Object -First 1
                Write-Verbose "    Found group: $($null -ne $group) - $($group.displayName) - ID: $($pimAssignment.PrincipalId)"
                if ($group) {
                    if (-not $nodeIndex.ContainsKey($group.id)) {
                        Write-Verbose "      Adding group node: $($group.displayName)"
                        $groupShape = & $resolveGroupShape $group
                        $null = $nodes.Add(@{
                            id = $group.id
                            label = $group.displayName
                            type = 'group'
                            shape = $groupShape
                            isPIMEnabled = [bool]$group.isPIMEnabled
                            isAssignableToRole = $group.isAssignableToRole
                            securityEnabled = $group.securityEnabled
                        })
                        $nodeIndex[$group.id] = $nodes.Count - 1
                    } else {
                        Write-Verbose "      Group node already exists: $($group.displayName)"
                    }
                    Write-Verbose "      Adding edge: $($group.displayName) -> $($pimAssignment.RoleName)"
                    $null = $edges.Add(@{
                        from = $group.id
                        to = $roleId
                        type = 'has_role'
                        label = $assignmentLabel
                        isPIM = $true
                    })
                }
            }
            'servicePrincipal' {
                $sp = $ServicePrincipals | Where-Object { $_.id -eq $pimAssignment.PrincipalId } | Select-Object -First 1
                if ($sp) {
                    if (-not $nodeIndex.ContainsKey($sp.id)) {
                        $null = $nodes.Add(@{
                            id = $sp.id
                            label = $sp.displayName
                            type = 'servicePrincipal'
                            appId = $sp.appId
                            accountEnabled = $sp.accountEnabled
                        })
                        $nodeIndex[$sp.id] = $nodes.Count - 1
                    }
                    $null = $edges.Add(@{
                        from = $sp.id
                        to = $roleId
                        type = 'has_role'
                        label = $assignmentLabel
                        isPIM = $true
                    })
                }
            }
        }
    }
    
    # Add group membership edges
    foreach ($groupId in $GroupMemberships.Keys) {
        $group = $Groups | Where-Object { $_.id -eq $groupId } | Select-Object -First 1
        if ($group) {
            if (-not $nodeIndex.ContainsKey($group.id)) {
                $groupShape = & $resolveGroupShape $group
                $null = $nodes.Add(@{
                    id = $group.id
                    label = $group.displayName
                    type = 'group'
                    shape = $groupShape
                    isPIMEnabled = [bool]$group.isPIMEnabled
                    isAssignableToRole = $group.isAssignableToRole
                    securityEnabled = $group.securityEnabled
                })
                $nodeIndex[$group.id] = $nodes.Count - 1
            }
            
            foreach ($member in $GroupMemberships[$groupId]) {
                $memberType = if ($member.'@odata.type') { 
                    $member.'@odata.type' -replace '#microsoft.graph.', '' 
                } else { 
                    'unknown' 
                }
                
                # Check if this is a PIM-eligible member (works for both hashtables and PSCustomObjects)
                $isPIMEligible = if ($member -is [hashtable]) {
                    $member.ContainsKey('isPIMEligible') -and $member.isPIMEligible
                } elseif ($member.PSObject.Properties.Name -contains 'isPIMEligible') {
                    $member.isPIMEligible
                } else {
                    $false
                }
                $membershipLabel = if ($isPIMEligible) { 'PIM Eligible' } else { 'Member' }
                
                switch ($memberType) {
                    'user' {
                        $user = $Users | Where-Object { $_.id -eq $member.id } | Select-Object -First 1
                        if ($user) {
                            & $ensureUserNode $user
                            $null = $edges.Add(@{
                                from = $user.id
                                to = $group.id
                                type = 'member_of'
                                label = $membershipLabel
                                isPIM = $isPIMEligible
                            })
                        }
                    }
                    'group' {
                        $nestedGroup = $Groups | Where-Object { $_.id -eq $member.id } | Select-Object -First 1
                        if ($nestedGroup) {
                            if (-not $nodeIndex.ContainsKey($nestedGroup.id)) {
                                $groupShape = & $resolveGroupShape $nestedGroup
                                $null = $nodes.Add(@{
                                    id = $nestedGroup.id
                                    label = $nestedGroup.displayName
                                    type = 'group'
                                    shape = $groupShape
                                    isPIMEnabled = [bool]$nestedGroup.isPIMEnabled
                                    isAssignableToRole = $nestedGroup.isAssignableToRole
                                    securityEnabled = $nestedGroup.securityEnabled
                                })
                                $nodeIndex[$nestedGroup.id] = $nodes.Count - 1
                            }
                            $null = $edges.Add(@{
                                from = $nestedGroup.id
                                to = $group.id
                                type = 'member_of'
                                label = 'Nested'
                            })
                        }
                    }
                }
            }
        }
    }
    
    # Add group ownership edges
    foreach ($groupId in $GroupOwners.Keys) {
        $group = $Groups | Where-Object { $_.id -eq $groupId } | Select-Object -First 1
        if ($group) {
            if (-not $nodeIndex.ContainsKey($group.id)) {
                $groupShape = & $resolveGroupShape $group
                $null = $nodes.Add(@{
                    id = $group.id
                    label = $group.displayName
                    type = 'group'
                    shape = $groupShape
                    isPIMEnabled = [bool]$group.isPIMEnabled
                    isAssignableToRole = $group.isAssignableToRole
                    securityEnabled = $group.securityEnabled
                })
                $nodeIndex[$group.id] = $nodes.Count - 1
            }
            
            foreach ($owner in $GroupOwners[$groupId]) {
                $user = $Users | Where-Object { $_.id -eq $owner.id } | Select-Object -First 1
                if ($user) {
                    & $ensureUserNode $user
                    $null = $edges.Add(@{
                        from = $user.id
                        to = $group.id
                        type = 'owns'
                        label = 'Owner'
                    })
                }
            }
        }
    }
    
    # Add service principal ownership edges
    foreach ($spId in $SPOwners.Keys) {
        $sp = $ServicePrincipals | Where-Object { $_.id -eq $spId } | Select-Object -First 1
        if ($sp) {
            if (-not $nodeIndex.ContainsKey($sp.id)) {
                $null = $nodes.Add(@{
                    id = $sp.id
                    label = $sp.displayName
                    type = 'servicePrincipal'
                    appId = $sp.appId
                    accountEnabled = $sp.accountEnabled
                })
                $nodeIndex[$sp.id] = $nodes.Count - 1
            }
            
            foreach ($owner in $SPOwners[$spId]) {
                $user = $Users | Where-Object { $_.id -eq $owner.id } | Select-Object -First 1
                if ($user) {
                    & $ensureUserNode $user
                    $null = $edges.Add(@{
                        from = $user.id
                        to = $sp.id
                        type = 'owns'
                        label = 'Owner'
                    })
                }
            }
        }
    }
    
    # Add service principal app role assignment edges (users/groups assigned to SP)
    foreach ($spId in $SPAppRoleAssignments.Keys) {
        $sp = $ServicePrincipals | Where-Object { $_.id -eq $spId } | Select-Object -First 1
        if ($sp) {
            if (-not $nodeIndex.ContainsKey($sp.id)) {
                $null = $nodes.Add(@{
                    id = $sp.id
                    label = $sp.displayName
                    type = 'servicePrincipal'
                    appId = $sp.appId
                    accountEnabled = $sp.accountEnabled
                })
                $nodeIndex[$sp.id] = $nodes.Count - 1
            }
            
            foreach ($assignment in $SPAppRoleAssignments[$spId]) {
                $principalType = $assignment.principalType
                
                if ($principalType -eq 'User') {
                    $user = $Users | Where-Object { $_.id -eq $assignment.principalId } | Select-Object -First 1
                    if ($user) {
                        & $ensureUserNode $user
                        $null = $edges.Add(@{
                            from = $user.id
                            to = $sp.id
                            type = 'assigned_to'
                            label = 'Assigned'
                        })
                    }
                }
                elseif ($principalType -eq 'Group') {
                    $group = $Groups | Where-Object { $_.id -eq $assignment.principalId } | Select-Object -First 1
                    if ($group) {
                        if (-not $nodeIndex.ContainsKey($group.id)) {
                            $groupShape = & $resolveGroupShape $group
                            $null = $nodes.Add(@{
                                id = $group.id
                                label = $group.displayName
                                type = 'group'
                                shape = $groupShape
                                isPIMEnabled = [bool]$group.isPIMEnabled
                                isAssignableToRole = $group.isAssignableToRole
                                securityEnabled = $group.securityEnabled
                            })
                            $nodeIndex[$group.id] = $nodes.Count - 1
                        }
                        $null = $edges.Add(@{
                            from = $group.id
                            to = $sp.id
                            type = 'assigned_to'
                            label = 'Assigned'
                        })
                    }
                }
            }
        }
    }
    
    # Add app registration ownership edges
    foreach ($appId in $AppOwners.Keys) {
        $app = $AppRegistrations | Where-Object { $_.id -eq $appId } | Select-Object -First 1
        if ($app) {
            if (-not $nodeIndex.ContainsKey($app.id)) {
                $null = $nodes.Add(@{
                    id = $app.id
                    label = $app.displayName
                    type = 'application'
                    appId = $app.appId
                })
                $nodeIndex[$app.id] = $nodes.Count - 1
            }
            
            foreach ($owner in $AppOwners[$appId]) {
                $user = $Users | Where-Object { $_.id -eq $owner.id } | Select-Object -First 1
                if ($user) {
                    & $ensureUserNode $user
                    $null = $edges.Add(@{
                        from = $user.id
                        to = $app.id
                        type = 'owns'
                        label = 'Owner'
                    })
                }
            }
        }
    }
    
    # Link app registrations to their service principals
    foreach ($app in $AppRegistrations) {
        $sp = $ServicePrincipals | Where-Object { $_.appId -eq $app.appId } | Select-Object -First 1
        if ($sp) {
            if (-not $nodeIndex.ContainsKey($app.id)) {
                $null = $nodes.Add(@{
                    id = $app.id
                    label = $app.displayName
                    type = 'application'
                    appId = $app.appId
                })
                $nodeIndex[$app.id] = $nodes.Count - 1
            }
            if (-not $nodeIndex.ContainsKey($sp.id)) {
                $null = $nodes.Add(@{
                    id = $sp.id
                    label = $sp.displayName
                    type = 'servicePrincipal'
                    appId = $sp.appId
                    accountEnabled = $sp.accountEnabled
                })
                $nodeIndex[$sp.id] = $nodes.Count - 1
            }
            $null = $edges.Add(@{
                from = $app.id
                to = $sp.id
                type = 'has_service_principal'
                label = 'Creates'
            })
        }
    }

    # First pass: Track all granted permissions to avoid duplicate edges
    $grantedPermissions = @{}
    foreach ($sp in $ServicePrincipals) {
        $hasAppPerms = $sp.PSObject.Properties.Name -contains 'GrantedApplicationPermissions' -and $sp.GrantedApplicationPermissions.Count -gt 0
        $hasDelegatedPerms = $sp.PSObject.Properties.Name -contains 'GrantedDelegatedPermissions' -and $sp.GrantedDelegatedPermissions.Count -gt 0
        
        if ($hasAppPerms) {
            foreach ($assignment in $sp.GrantedApplicationPermissions) {
                $resourceKey = if ($servicePrincipalsById.ContainsKey($assignment.ResourceId) -and $servicePrincipalsById[$assignment.ResourceId].appId) {
                    $servicePrincipalsById[$assignment.ResourceId].appId
                } else {
                    $assignment.ResourceId
                }
                $identifier = if ($assignment.AppRoleId) { $assignment.AppRoleId } else { $assignment.AppRoleValue }
                $permissionNodeId = & $buildPermissionNodeId $resourceKey $identifier
                $grantedPermissions["$($sp.appId)::$permissionNodeId"] = $true
            }
        }
        
        if ($hasDelegatedPerms) {
            foreach ($grant in $sp.GrantedDelegatedPermissions) {
                $resourceKey = if ($servicePrincipalsById.ContainsKey($grant.ResourceId) -and $servicePrincipalsById[$grant.ResourceId].appId) {
                    $servicePrincipalsById[$grant.ResourceId].appId
                } else {
                    $grant.ResourceId
                }
                
                $scopeEntries = if ($grant.ResolvedScopes) { $grant.ResolvedScopes } else { @() }
                if ($scopeEntries.Count -eq 0 -and $grant.RawScope) {
                    $scopeEntries = @([PSCustomObject]@{ ScopeId = $null; ScopeName = $grant.RawScope })
                }
                
                foreach ($scopeEntry in $scopeEntries) {
                    $identifier = if ($scopeEntry.ScopeId) { $scopeEntry.ScopeId } else { $scopeEntry.ScopeName }
                    if (-not $identifier -and $grant.GrantId) { $identifier = "$($grant.GrantId)-scope" }
                    $permissionNodeId = & $buildPermissionNodeId $resourceKey $identifier
                    $grantedPermissions["$($sp.appId)::$permissionNodeId"] = $true
                }
            }
        }
    }

    # Visualize requested API permissions on app registrations
    foreach ($app in $AppRegistrations) {
        if (-not $nodeIndex.ContainsKey($app.id)) {
            $null = $nodes.Add(@{
                id = $app.id
                label = $app.displayName
                type = 'application'
                appId = $app.appId
            })
            $nodeIndex[$app.id] = $nodes.Count - 1
        }

        if (-not $app.ApiPermissions) { continue }

        foreach ($resource in $app.ApiPermissions) {
            if (-not $resource.ResourceAppId) { continue }
            $resourceSp = $null
            if ($servicePrincipalsByAppId.ContainsKey($resource.ResourceAppId)) {
                $resourceSp = $servicePrincipalsByAppId[$resource.ResourceAppId]
            }
            $resourceName = if ($resourceSp) { $resourceSp.displayName } else { $resource.ResourceAppId }
            $resourceName = & $normalizeResourceName $resourceName $resource.ResourceAppId

            foreach ($permission in $resource.ResourceAccess) {
                $permissionType = if ($permission.type) { $permission.type } else { 'Unknown' }
                $permissionDefinition = $null
                if ($resourceSp) {
                    if ($permissionType -eq 'Scope' -and $resourceSp.oauth2PermissionScopes) {
                        $permissionDefinition = $resourceSp.oauth2PermissionScopes | Where-Object { $_.id -eq $permission.id } | Select-Object -First 1
                    }
                    elseif ($permissionType -eq 'Role' -and $resourceSp.appRoles) {
                        $permissionDefinition = $resourceSp.appRoles | Where-Object { $_.id -eq $permission.id } | Select-Object -First 1
                    }
                }

                $permissionMetadata = if (-not $permissionDefinition) { & $resolvePermissionMetadata $permission.id } else { $null }

                $permissionValue = if ($permissionDefinition -and $permissionDefinition.value) {
                    $permissionDefinition.value
                }
                elseif ($permissionMetadata -and $permissionMetadata.PermissionValue) {
                    $permissionMetadata.PermissionValue
                }
                elseif ($permission.id) {
                    $permission.id
                }
                else {
                    'Unknown Permission'
                }

                $displayText = $null
                if ($permissionDefinition) {
                    $displayText = if ($permissionType -eq 'Scope') { $permissionDefinition.adminConsentDisplayName } else { $permissionDefinition.displayName }
                }
                if (-not $displayText -and $permissionMetadata -and $permissionMetadata.DisplayName) {
                    $displayText = $permissionMetadata.DisplayName
                }
                if (-not $displayText) {
                    $displayText = $permissionValue
                }

                $permissionDescription = $null
                if ($permissionDefinition) {
                    if ($permissionType -eq 'Scope' -and $permissionDefinition.adminConsentDescription) {
                        $permissionDescription = $permissionDefinition.adminConsentDescription
                    }
                    elseif ($permissionDefinition.description) {
                        $permissionDescription = $permissionDefinition.description
                    }
                }
                if (-not $permissionDescription -and $permissionMetadata -and $permissionMetadata.Description) {
                    $permissionDescription = $permissionMetadata.Description
                }

                $labelValue = if ($permissionValue) { $permissionValue } elseif ($displayText) { $displayText } else { $permission.id }
                if (-not $labelValue) { $labelValue = 'API Permission' }
                $permissionLabel = "$($resourceName): $labelValue"

                $identifier = if ($permissionDefinition -and $permissionDefinition.id) { $permissionDefinition.id } elseif ($permission.id) { $permission.id } else { $permissionValue }
                $permissionNodeId = & $buildPermissionNodeId $resource.ResourceAppId $identifier $permissionValue

                & $ensurePermissionNode $permissionNodeId $permissionLabel $resourceName $permissionValue $permissionType $displayText $permissionDescription ($permissionMetadata.Audience) ($permissionMetadata.AdminConsentRequired)

                # Only add requests_permission edge if this permission is NOT granted
                $isGranted = $grantedPermissions.ContainsKey("$($app.appId)::$permissionNodeId")
                if (-not $isGranted) {
                    $edgeKey = "requests::$($app.id)->$permissionNodeId"
                    if (-not $permissionAssociationTracker.Contains($edgeKey)) {
                        $null = $edges.Add(@{
                            from = $app.id
                            to = $permissionNodeId
                            type = 'requests_permission'
                            label = if ($permissionType -eq 'Scope') { 'Delegated' } else { 'Application' }
                            grantType = if ($permissionType -eq 'Scope') { 'Delegated' } else { 'Application' }
                        })
                        [void]$permissionAssociationTracker.Add($edgeKey)
                    }
                }
            }
        }
    }

    # Visualize granted API permissions on service principals
    foreach ($sp in $ServicePrincipals) {
        $hasAppPerms = $sp.PSObject.Properties.Name -contains 'GrantedApplicationPermissions' -and $sp.GrantedApplicationPermissions.Count -gt 0
        $hasDelegatedPerms = $sp.PSObject.Properties.Name -contains 'GrantedDelegatedPermissions' -and $sp.GrantedDelegatedPermissions.Count -gt 0
        if (-not ($hasAppPerms -or $hasDelegatedPerms)) { continue }

        if (-not $nodeIndex.ContainsKey($sp.id)) {
            $null = $nodes.Add(@{
                id = $sp.id
                label = $sp.displayName
                type = 'servicePrincipal'
                appId = $sp.appId
                accountEnabled = $sp.accountEnabled
            })
            $nodeIndex[$sp.id] = $nodes.Count - 1
        }

        if ($hasAppPerms) {
            foreach ($assignment in $sp.GrantedApplicationPermissions) {
                $resourceSp = if ($servicePrincipalsById.ContainsKey($assignment.ResourceId)) {
                    $servicePrincipalsById[$assignment.ResourceId]
                } else { $null }
                $resourceName = if ($assignment.ResourceDisplayName) { $assignment.ResourceDisplayName } elseif ($resourceSp) { $resourceSp.displayName } else { $assignment.ResourceId }
                $resourceKey = if ($resourceSp -and $resourceSp.appId) { $resourceSp.appId } else { $assignment.ResourceId }
                $resourceName = & $normalizeResourceName $resourceName $resourceKey

                $permissionMetadata = if ($assignment.AppRoleId) { & $resolvePermissionMetadata $assignment.AppRoleId } else { $null }
                $permissionValue = if ($assignment.AppRoleValue) {
                    $assignment.AppRoleValue
                }
                elseif ($permissionMetadata -and $permissionMetadata.PermissionValue) {
                    $permissionMetadata.PermissionValue
                }
                elseif ($assignment.AppRoleId) {
                    $assignment.AppRoleId
                }
                else {
                    'Unknown Permission'
                }

                $displayGrantName = if ($assignment.AppRoleDisplayName) {
                    $assignment.AppRoleDisplayName
                }
                elseif ($permissionMetadata -and $permissionMetadata.DisplayName) {
                    $permissionMetadata.DisplayName
                }
                else {
                    $permissionValue
                }

                $permissionDescription = if ($assignment.AppRoleDescription) {
                    $assignment.AppRoleDescription
                }
                elseif ($permissionMetadata -and $permissionMetadata.Description) {
                    $permissionMetadata.Description
                }
                else {
                    $null
                }

                $permissionLabel = "$($resourceName): $permissionValue"

                $identifier = if ($assignment.AppRoleId) { $assignment.AppRoleId } else { $permissionValue }
                $permissionNodeId = & $buildPermissionNodeId $resourceKey $identifier $permissionValue

                & $ensurePermissionNode $permissionNodeId $permissionLabel $resourceName $permissionValue 'Role' $displayGrantName $permissionDescription ($permissionMetadata.Audience) ($permissionMetadata.AdminConsentRequired)
                & $linkPermissionToRoles $permissionNodeId $permissionValue

                $edgeKey = "grant-app::$($sp.id)->$permissionNodeId::$($assignment.AssignmentId)"
                if (-not $permissionAssociationTracker.Contains($edgeKey)) {
                    $null = $edges.Add(@{
                        from = $sp.id
                        to = $permissionNodeId
                        type = 'has_permission'
                        label = 'Application Grant'
                        grantId = $assignment.AssignmentId
                        grantType = 'Application'
                    })
                    [void]$permissionAssociationTracker.Add($edgeKey)
                }
            }
        }

        if ($hasDelegatedPerms) {
            foreach ($grant in $sp.GrantedDelegatedPermissions) {
                $resourceSp = if ($servicePrincipalsById.ContainsKey($grant.ResourceId)) {
                    $servicePrincipalsById[$grant.ResourceId]
                } else { $null }
                $resourceName = if ($grant.ResourceDisplayName) { $grant.ResourceDisplayName } elseif ($resourceSp) { $resourceSp.displayName } else { $grant.ResourceId }
                $resourceKey = if ($resourceSp -and $resourceSp.appId) { $resourceSp.appId } else { $grant.ResourceId }
                $resourceName = & $normalizeResourceName $resourceName $resourceKey

                $scopeEntries = if ($grant.ResolvedScopes) { $grant.ResolvedScopes } else { @() }
                if ($scopeEntries.Count -eq 0 -and $grant.RawScope) {
                    $scopeEntries = @([PSCustomObject]@{ ScopeId = $null; ScopeName = $grant.RawScope; ScopeDisplayName = $grant.RawScope; ScopeDescription = $null })
                }

                foreach ($scopeEntry in $scopeEntries) {
                    $identifier = if ($scopeEntry.ScopeId) { $scopeEntry.ScopeId } else { $scopeEntry.ScopeName }
                    if (-not $identifier -and $grant.GrantId) { $identifier = "$($grant.GrantId)-scope" }
                    $permissionNodeId = & $buildPermissionNodeId $resourceKey $identifier $permissionValue

                    $permissionMetadata = if ($scopeEntry.ScopeId) { & $resolvePermissionMetadata $scopeEntry.ScopeId } else { $null }
                    $displayName = if ($scopeEntry.ScopeDisplayName) {
                        $scopeEntry.ScopeDisplayName
                    }
                    elseif ($scopeEntry.ScopeName) {
                        $scopeEntry.ScopeName
                    }
                    elseif ($permissionMetadata -and $permissionMetadata.DisplayName) {
                        $permissionMetadata.DisplayName
                    }
                    else {
                        'Delegated Scope'
                    }
                    $permissionValue = if ($scopeEntry.ScopeName) {
                        $scopeEntry.ScopeName
                    }
                    elseif ($permissionMetadata -and $permissionMetadata.PermissionValue) {
                        $permissionMetadata.PermissionValue
                    }
                    else {
                        $displayName
                    }
                    $permissionDescription = if ($scopeEntry.ScopeDescription) {
                        $scopeEntry.ScopeDescription
                    }
                    elseif ($permissionMetadata -and $permissionMetadata.Description) {
                        $permissionMetadata.Description
                    }
                    else {
                        $null
                    }

                    $permissionLabel = "$( $resourceName ): $permissionValue"

                    & $ensurePermissionNode $permissionNodeId $permissionLabel $resourceName $permissionValue 'Scope' $displayName $permissionDescription ($permissionMetadata.Audience) ($permissionMetadata.AdminConsentRequired)
                    & $linkPermissionToRoles $permissionNodeId $permissionValue

                    $consentLabel = switch ($grant.ConsentType) {
                        'AllPrincipals' { 'Delegated (Tenant-wide)' }
                        'Principal' { 'Delegated (Per-user)' }
                        Default { 'Delegated' }
                    }

                    $edgeKey = "grant-delegated::$($sp.id)->$permissionNodeId::$($grant.GrantId)::$($scopeEntry.ScopeName)"
                    if (-not $permissionAssociationTracker.Contains($edgeKey)) {
                        $null = $edges.Add(@{
                            from = $sp.id
                            to = $permissionNodeId
                            type = 'has_permission'
                            label = $consentLabel
                            grantId = $grant.GrantId
                            consentType = $grant.ConsentType
                            principalId = $grant.PrincipalId
                            grantType = 'Delegated'
                        })
                        [void]$permissionAssociationTracker.Add($edgeKey)
                    }
                }
            }
        }
    }
    
    # Add "can_manage" edges for administrative roles with app/SP management capabilities
    $appManagementRoles = @(
        'Cloud Application Administrator',
        'Application Administrator',
        'Hybrid Identity Administrator'
    )

    # Find all principals with app management roles (from both direct and PIM)
    $allRoleAssignments = @($RoleAssignments; $PIMAssignments)
    $appAdmins = $allRoleAssignments | Where-Object { $appManagementRoles -contains $_.RoleName }

    foreach ($roleName in $appManagementRoles) {
        $roleAssignments = $appAdmins | Where-Object { $_.RoleName -eq $roleName }
        if (-not $roleAssignments) { continue }

        $roleNodeId = "role-$roleName"
        if (-not $nodeIndex.ContainsKey($roleNodeId)) {
            $isHighPrivilege = $highPrivilegeRoles -contains $roleName
            $null = $nodes.Add(@{
                id = $roleNodeId
                label = $roleName
                type = 'role'
                isPrivileged = $true
                isHighPrivilege = $isHighPrivilege
            })
            $nodeIndex[$roleNodeId] = $nodes.Count - 1
        }

        foreach ($sp in $ServicePrincipals) {
            $spHasRole = $allRoleAssignments | Where-Object { $_.MemberId -eq $sp.id }
            if ($spHasRole -and $nodeIndex.ContainsKey($sp.id)) {
                $null = $edges.Add(@{
                    from = $roleNodeId
                    to = $sp.id
                    type = 'can_manage'
                    label = 'Can Manage'
                    sourceRole = $roleName
                })
            }
        }

        foreach ($app in $AppRegistrations) {
            $sp = $ServicePrincipals | Where-Object { $_.appId -eq $app.appId } | Select-Object -First 1
            if ($sp) {
                $spHasRole = $allRoleAssignments | Where-Object { $_.MemberId -eq $sp.id }
                if ($spHasRole -and $nodeIndex.ContainsKey($app.id)) {
                    $null = $edges.Add(@{
                        from = $roleNodeId
                        to = $app.id
                        type = 'can_manage'
                        label = 'Can Manage'
                        sourceRole = $roleName
                    })
                }
            }
        }
    }

    Write-Verbose "Built graph with $($nodes.Count) nodes and $($edges.Count) edges"
    
    # Calculate escalation paths - mark edges that are part of paths to critical high-privilege roles
    Write-Verbose "Calculating escalation paths to critical high-privilege roles..."
    
    # Define critical roles for escalation path analysis (most dangerous)
    $criticalRoles = @(
        'Global Administrator',
        'Privileged Role Administrator',
        'Application Administrator',
        'Cloud Application Administrator'
    )
    
    $criticalRoleNodes = $nodes | Where-Object { $_.type -eq 'role' -and $criticalRoles -contains $_.label }
    $escalationEdges = [System.Collections.Generic.HashSet[string]]::new()
    
    # Build reverse adjacency list (to -> from) for backtracking
    $reverseAdjacency = @{}
    foreach ($edge in $edges) {
        if (-not $reverseAdjacency.ContainsKey($edge.to)) {
            $reverseAdjacency[$edge.to] = @()
        }
        $reverseAdjacency[$edge.to] += @{
            from = $edge.from
            to = $edge.to
            type = $edge.type
            label = $edge.label
        }
    }
    
    # BFS from each critical role backwards to find all paths
    foreach ($roleNode in $criticalRoleNodes) {
        $visited = @{}
        $queue = [System.Collections.Queue]::new()
        $queue.Enqueue($roleNode.id)
        $visited[$roleNode.id] = $true
        
        while ($queue.Count -gt 0) {
            $currentId = $queue.Dequeue()
            
            if ($reverseAdjacency.ContainsKey($currentId)) {
                foreach ($edgeInfo in $reverseAdjacency[$currentId]) {
                    $edgeKey = "$($edgeInfo.from)->$($edgeInfo.to)"
                    $null = $escalationEdges.Add($edgeKey)
                    
                    if (-not $visited.ContainsKey($edgeInfo.from)) {
                        $visited[$edgeInfo.from] = $true
                        $queue.Enqueue($edgeInfo.from)
                    }
                }
            }
        }
    }
    
    # Mark edges that are part of escalation paths to critical roles
    $edgesWithEscalationMarker = foreach ($edge in $edges) {
        $edgeKey = "$($edge.from)->$($edge.to)"
        $isEscalationPath = $escalationEdges.Contains($edgeKey)
        
        # Create new hashtable with all original properties plus isEscalationPath
        $newEdge = @{
            from = $edge.from
            to = $edge.to
            type = $edge.type
            label = $edge.label
            isEscalationPath = $isEscalationPath
        }
        
        # Copy any additional properties
        if ($edge.ContainsKey('isPIM')) { $newEdge.isPIM = $edge.isPIM }
        
        $newEdge
    }
    
    Write-Verbose "Identified $($escalationEdges.Count) edges that are part of escalation paths to critical roles"
    
    return @{
        nodes = $nodes
        edges = $edgesWithEscalationMarker
        escalationStats = @{
            totalEdges = $edges.Count
            escalationEdges = $escalationEdges.Count
            criticalRoles = $criticalRoleNodes.Count
        }
    }
}
