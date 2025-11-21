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
    
    foreach ($roleName in $allRoles) {
        $roleId = "role-$roleName"
        if (-not $nodeIndex.ContainsKey($roleId)) {
            $isHighPrivilege = $highPrivilegeRoles -contains $roleName
            $null = $nodes.Add(@{
                id = $roleId
                label = $roleName
                type = 'role'
                isPrivileged = $true
                isHighPrivilege = $isHighPrivilege
            })
            $nodeIndex[$roleId] = $nodes.Count - 1
        }
    }
    
    # Add nodes and edges for direct role assignments
    foreach ($assignment in $RoleAssignments) {
        $roleId = "role-$($assignment.RoleName)"
        
        # Determine the principal type and add node
        switch ($assignment.MemberType) {
            'user' {
                $user = $Users | Where-Object { $_.id -eq $assignment.MemberId } | Select-Object -First 1
                if ($user) {
                    if (-not $nodeIndex.ContainsKey($user.id)) {
                        $null = $nodes.Add(@{
                            id = $user.id
                            label = $user.displayName
                            type = 'user'
                            userPrincipalName = $user.userPrincipalName
                            accountEnabled = $user.accountEnabled
                        })
                        $nodeIndex[$user.id] = $nodes.Count - 1
                    }
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
                    if (-not $nodeIndex.ContainsKey($user.id)) {
                        $null = $nodes.Add(@{
                            id = $user.id
                            label = $user.displayName
                            type = 'user'
                            userPrincipalName = $user.userPrincipalName
                            accountEnabled = $user.accountEnabled
                        })
                        $nodeIndex[$user.id] = $nodes.Count - 1
                    }
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
                            if (-not $nodeIndex.ContainsKey($user.id)) {
                                $null = $nodes.Add(@{
                                    id = $user.id
                                    label = $user.displayName
                                    type = 'user'
                                    userPrincipalName = $user.userPrincipalName
                                    accountEnabled = $user.accountEnabled
                                })
                                $nodeIndex[$user.id] = $nodes.Count - 1
                            }
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
                    if (-not $nodeIndex.ContainsKey($user.id)) {
                        $null = $nodes.Add(@{
                            id = $user.id
                            label = $user.displayName
                            type = 'user'
                            userPrincipalName = $user.userPrincipalName
                            accountEnabled = $user.accountEnabled
                        })
                        $nodeIndex[$user.id] = $nodes.Count - 1
                    }
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
                    if (-not $nodeIndex.ContainsKey($user.id)) {
                        $null = $nodes.Add(@{
                            id = $user.id
                            label = $user.displayName
                            type = 'user'
                            userPrincipalName = $user.userPrincipalName
                            accountEnabled = $user.accountEnabled
                        })
                        $nodeIndex[$user.id] = $nodes.Count - 1
                    }
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
                        if (-not $nodeIndex.ContainsKey($user.id)) {
                            $null = $nodes.Add(@{
                                id = $user.id
                                label = $user.displayName
                                type = 'user'
                                userPrincipalName = $user.userPrincipalName
                                accountEnabled = $user.accountEnabled
                            })
                            $nodeIndex[$user.id] = $nodes.Count - 1
                        }
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
                    if (-not $nodeIndex.ContainsKey($user.id)) {
                        $null = $nodes.Add(@{
                            id = $user.id
                            label = $user.displayName
                            type = 'user'
                            userPrincipalName = $user.userPrincipalName
                            accountEnabled = $user.accountEnabled
                        })
                        $nodeIndex[$user.id] = $nodes.Count - 1
                    }
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
    
    # Add "can_manage" edges for administrative roles with app/SP management capabilities
    $appManagementRoles = @(
        'Cloud Application Administrator',
        'Application Administrator',
        'Hybrid Identity Administrator'
    )

    # Find all principals with app management roles (from both direct and PIM)
    $allRoleAssignments = @($RoleAssignments; $PIMAssignments)
    $appAdmins = $allRoleAssignments | Where-Object { $appManagementRoles -contains $_.RoleName }

    foreach ($admin in $appAdmins) {
        $principalId = if ($admin.MemberId) { $admin.MemberId } else { $admin.PrincipalId }

        # Add can_manage edges to all service principals with roles
        foreach ($sp in $ServicePrincipals) {
            $spHasRole = $allRoleAssignments | Where-Object { $_.MemberId -eq $sp.id }
            if ($spHasRole) {
                # Ensure both nodes exist
                if ($nodeIndex.ContainsKey($principalId) -and $nodeIndex.ContainsKey($sp.id)) {
                    $null = $edges.Add(@{
                        from = $principalId
                        to = $sp.id
                        type = 'can_manage'
                        label = 'Can Manage'
                        isPIM = $admin.PSObject.Properties.Name -contains 'AssignmentType'
                    })
                }
            }
        }

        # Add can_manage edges to all app registrations
        foreach ($app in $AppRegistrations) {
            # Only add if app is linked to a privileged SP
            $sp = $ServicePrincipals | Where-Object { $_.appId -eq $app.appId } | Select-Object -First 1
            if ($sp) {
                $spHasRole = $allRoleAssignments | Where-Object { $_.MemberId -eq $sp.id }
                if ($spHasRole) {
                    # Ensure both nodes exist
                    if ($nodeIndex.ContainsKey($principalId) -and $nodeIndex.ContainsKey($app.id)) {
                        $null = $edges.Add(@{
                            from = $principalId
                            to = $app.id
                            type = 'can_manage'
                            label = 'Can Manage'
                            isPIM = $admin.PSObject.Properties.Name -contains 'AssignmentType'
                        })
                    }
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
