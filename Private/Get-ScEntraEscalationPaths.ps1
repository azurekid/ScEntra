function Get-ScEntraEscalationPaths {
    <#
    .SYNOPSIS
        Analyzes and identifies privilege escalation paths

    .DESCRIPTION
        Analyzes nested group memberships, role assignments, and ownership patterns to identify
        potential privilege escalation risks. Uses batch processing to minimize Graph API calls.

    .PARAMETER Users
        Array of users from Get-ScEntraUsers

    .PARAMETER Groups
        Array of groups from Get-ScEntraGroups

    .PARAMETER RoleAssignments
        Array of role assignments from Get-ScEntraRoleAssignments

    .PARAMETER PIMAssignments
        Array of PIM assignments from Get-ScEntraPIMAssignments

    .PARAMETER ServicePrincipals
        Array of service principals from Get-ScEntraServicePrincipals

    .PARAMETER AppRegistrations
        Array of app registrations from Get-ScEntraAppRegistrations

    .EXAMPLE
        $escalationPaths = Get-ScEntraEscalationPaths -Users $users -Groups $groups -RoleAssignments $roles -PIMAssignments $pim
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Users,

        [Parameter(Mandatory = $true)]
        [array]$Groups,

        [Parameter(Mandatory = $true)]
        [array]$RoleAssignments,

        [Parameter(Mandatory = $false)]
        [array]$PIMAssignments = @(),

        [Parameter(Mandatory = $false)]
        [array]$ServicePrincipals = @(),

        [Parameter(Mandatory = $false)]
        [array]$AppRegistrations = @()
    )

    if (-not (Test-GraphConnection)) {
        return @()
    }

    # Check required permissions
    $requiredPermissions = @('PrivilegedAccess.Read.AzureADGroup', 'Group.Read.All')
    if (-not (Test-GraphPermissions -RequiredPermissions $requiredPermissions -ResourceName "Escalation Paths (PIM for Groups)")) {
        Write-Warning "Some escalation path analysis may be incomplete due to missing permissions."
    }

    Write-Verbose "Analyzing escalation paths..."

    $escalationRisks = @()

    $groupMemberships = @{}
    $groupOwners = @{}
    $spOwners = @{}
    $spAppRoleAssignments = @{}
    $appOwners = @{}

    $permissionEscalationMap = @(
        @{ Permission = 'Domain.ReadWrite.All'; Severity = 'Critical'; AttackPath = 'Can add/verify federated domains and forge SAML tokens for any hybrid user, including Global Administrator, if misused'; Recommendation = 'Restrict to trusted workloads only, enforce app instance property locks, prefer cloud-only privileged accounts'; Reference = 'Federated domain backdoor (Datadog Security Labs, 2025)'; },
        @{ Permission = 'RoleManagement.ReadWrite.Directory'; Severity = 'Critical'; AttackPath = 'Allows modification of privileged role assignments, effectively equivalent to Privileged Role Administrator'; Recommendation = 'Limit to break-glass workloads, monitor assignment events'; Reference = 'Microsoft Graph role management permissions'; },
        @{ Permission = 'AppRoleAssignment.ReadWrite.All'; Severity = 'High'; AttackPath = 'Can grant application permissions to any service principal, enabling lateral movement into higher-privileged apps'; Recommendation = 'Require justification and PIM for workloads with this permission'; Reference = 'Microsoft Graph application assignments'; },
        @{ Permission = 'Application.ReadWrite.All'; Severity = 'High'; AttackPath = 'Can add credentials and modify any application/service principal which enables service principal hijacking for privileged apps'; Recommendation = 'Enforce app instance property locks, move to managed identities with scoped permissions'; Reference = 'Semperis UnOAuthorized + Datadog first-party SP research'; },
        @{ Permission = 'Group.ReadWrite.All'; Severity = 'High'; AttackPath = 'Can modify membership of any Microsoft 365/role assignable group, enabling indirect elevation to platform roles'; Recommendation = 'Use administrative units and least privilege scopes; avoid granting to unattended apps'; Reference = 'Nested group escalation patterns'; },
        @{ Permission = 'Directory.ReadWrite.All'; Severity = 'Medium'; AttackPath = 'Broad ability to modify directory objects including users and devices which can be chained with other misconfigurations'; Recommendation = 'Swap for granular scopes or partition into administrative units'; Reference = 'Microsoft Graph directory write guidance'; },
        @{ Permission = 'DeviceManagementConfiguration.ReadWrite.All'; Severity = 'High'; AttackPath = 'Authorizes writing Intune device management scripts that run as SYSTEM on PAWs, enabling capture of Global Administrator sessions'; Recommendation = 'Require multi-admin approval for Intune changes and lock down workload identity usage'; Reference = 'Mandiant Intune lateral movement (2024)'; }
    )
    $permissionEscalationLookup = @{}
    foreach ($entry in $permissionEscalationMap) {
        $permissionEscalationLookup[$entry.Permission] = $entry
    }

    $groupsWithRoles = $RoleAssignments | Where-Object { $_.MemberType -eq 'group' } | Select-Object -ExpandProperty MemberId -Unique
    $pimEnabledGroupIds = $Groups | Where-Object { $_.isPIMEnabled -eq $true } | Select-Object -ExpandProperty id -Unique
    $roleEnabledGroups = $Groups | Where-Object { $_.isAssignableToRole -eq $true } | Select-Object -ExpandProperty id

    $relevantGroupIds = @($groupsWithRoles; $pimEnabledGroupIds; $roleEnabledGroups) | Select-Object -Unique

    Write-Host "Found $($roleEnabledGroups.Count) role-assignable groups" -ForegroundColor Yellow
    Write-Host "Found $($pimEnabledGroupIds.Count) PIM-enabled groups" -ForegroundColor Yellow
    Write-Host "Analyzing $($relevantGroupIds.Count) groups with role assignments or PIM eligibility (optimized)" -ForegroundColor Cyan

    $batchRequests = @()
    $requestId = 0

    foreach ($groupId in $relevantGroupIds) {
        $batchRequests += @{
            id      = "$requestId-members-$groupId"
            method  = "GET"
            url     = "/groups/$groupId/members?`$select=id,displayName,userPrincipalName&`$count=true"
            headers = @{
                "ConsistencyLevel" = "eventual"
            }
        }
        $requestId++

        if ($pimEnabledGroupIds -contains $groupId) {
            $batchRequests += @{
                id     = "$requestId-pim-eligible-$groupId"
                method = "GET"
                url    = "/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances?`$filter=groupId eq '$groupId'&`$expand=principal"
            }
            $requestId++
            
            $batchRequests += @{
                id     = "$requestId-pim-active-$groupId"
                method = "GET"
                url    = "/identityGovernance/privilegedAccess/group/assignmentScheduleInstances?`$filter=groupId eq '$groupId'&`$expand=principal"
            }
            $requestId++
        }

        $batchRequests += @{
            id     = "$requestId-owners-$groupId"
            method = "GET"
            url    = "/groups/$groupId/owners?`$select=id,displayName,userPrincipalName"
        }
        $requestId++

        if ($groupsWithRoles -contains $groupId) {
            $batchRequests += @{
                id      = "$requestId-transitive-$groupId"
                method  = "GET"
                url     = "/groups/$groupId/transitiveMembers?`$select=id&`$count=true"
                headers = @{
                    "ConsistencyLevel" = "eventual"
                }
            }
            $requestId++
        }
    }

    Write-Verbose "Fetching group data using batch requests ($($batchRequests.Count) requests for $($relevantGroupIds.Count) groups)"
    Write-Progress -Activity "Analyzing escalation paths" -Status "Fetching group membership data in batches" -PercentComplete 10 -Id 5

    $batchResponses = @{}
    if ($batchRequests.Count -gt 0) {
        try {
            $batchResponses = Invoke-GraphBatchRequest -Requests $batchRequests
        }
        catch {
            Write-Warning "Batch request failed, falling back to individual requests: $_"
        }
    }

    foreach ($groupId in $relevantGroupIds) {
        $membersResponseKey = $batchResponses.Keys | Where-Object { $_ -like "*-members-$groupId" } | Select-Object -First 1
        if ($membersResponseKey) {
            $membersResponse = $batchResponses[$membersResponseKey]
            if ($membersResponse -and $membersResponse.status -eq 200 -and $membersResponse.body.value) {
                $groupMemberships[$groupId] = $membersResponse.body.value
            }
        }
        else {
            try {
                $membersUri = "$script:GraphBaseUrl/groups/$groupId/members?`$select=id,displayName,userPrincipalName"
                $membersResult = Invoke-GraphRequest -Uri $membersUri -Method GET -ErrorAction SilentlyContinue
                if ($membersResult.value) {
                    $groupMemberships[$groupId] = $membersResult.value
                }
            }
            catch {
                Write-Verbose "Could not fetch members for group ${groupId}: $($_.Exception.Message)"
            }
        }

        # Get active PIM assignments first to identify truly active members
        $activePIMMembers = @()
        $pimActiveKey = $batchResponses.Keys | Where-Object { $_ -like "*-pim-active-$groupId" } | Select-Object -First 1
        if ($pimActiveKey) {
            $pimActiveResponse = $batchResponses[$pimActiveKey]
            if ($pimActiveResponse -and $pimActiveResponse.status -eq 200 -and $pimActiveResponse.body.value) {
                $activePIMMembers = $pimActiveResponse.body.value | Where-Object { $_.principal } | Select-Object -ExpandProperty principal | Select-Object -ExpandProperty id
                Write-Verbose "Found $($activePIMMembers.Count) active PIM members for group $groupId"
            }
        }
        
        # Now process eligible members
        $pimEligibleKey = $batchResponses.Keys | Where-Object { $_ -like "*-pim-eligible-$groupId" } | Select-Object -First 1
        if ($pimEligibleKey) {
            $pimEligibleResponse = $batchResponses[$pimEligibleKey]
            if ($pimEligibleResponse -and $pimEligibleResponse.status -eq 200 -and $pimEligibleResponse.body.value) {
                Write-Verbose "Found $($pimEligibleResponse.body.value.Count) PIM eligible members for group $groupId"

                if (-not $groupMemberships.ContainsKey($groupId)) {
                    $groupMemberships[$groupId] = @()
                }

                foreach ($eligibility in $pimEligibleResponse.body.value) {
                    if ($eligibility.principal -and $eligibility.principal.id) {
                        $principalId = $eligibility.principal.id
                        $isActive = $activePIMMembers -contains $principalId
                        
                        $existingMember = $groupMemberships[$groupId] | Where-Object { $_.id -eq $principalId } | Select-Object -First 1
                        
                        if ($existingMember) {
                            # Mark as PIM-eligible regardless of active status
                            # Users who activated their eligibility appear in both /members and eligibilitySchedules
                            $existingMember | Add-Member -NotePropertyName 'isPIMEligible' -NotePropertyValue $true -Force
                            $groupName = ($Groups | Where-Object { $_.id -eq $groupId } | Select-Object -First 1).displayName
                            $status = if ($isActive) { "(Active)" } else { "" }
                            Write-Host "  PIM Eligible $status`: $($existingMember.displayName) → $groupName" -ForegroundColor Magenta
                            Write-Verbose "  Marked existing member as PIM eligible: $($existingMember.displayName) (Active: $isActive)"
                        } else {
                            # Add user who is eligible but not yet activated (not in regular /members)
                            $fullUser = $Users | Where-Object { $_.id -eq $principalId } | Select-Object -First 1
                            if ($fullUser) {
                                $memberObject = @{
                                    id                = $fullUser.id
                                    displayName       = $fullUser.displayName
                                    userPrincipalName = $fullUser.userPrincipalName
                                    '@odata.type'     = '#microsoft.graph.user'
                                    isPIMEligible     = $true
                                }
                                $groupMemberships[$groupId] += $memberObject
                                $groupName = ($Groups | Where-Object { $_.id -eq $groupId } | Select-Object -First 1).displayName
                                Write-Host "  PIM Eligible (Not Activated): $($fullUser.displayName) → $groupName" -ForegroundColor Magenta
                                Write-Verbose "  Added PIM eligible-only member: $($fullUser.displayName)"
                            }
                        }
                    }
                }
            }
        }

        $ownersResponseKey = $batchResponses.Keys | Where-Object { $_ -like "*-owners-$groupId" } | Select-Object -First 1
        if ($ownersResponseKey) {
            $ownersResponse = $batchResponses[$ownersResponseKey]
            if ($ownersResponse -and $ownersResponse.status -eq 200 -and $ownersResponse.body.value) {
                $groupOwners[$groupId] = $ownersResponse.body.value
            }
        }
        else {
            try {
                $ownersUri = "$script:GraphBaseUrl/groups/$groupId/owners?`$select=id,displayName,userPrincipalName"
                $ownersResult = Invoke-GraphRequest -Uri $ownersUri -Method GET -ErrorAction SilentlyContinue
                if ($ownersResult.value) {
                    $groupOwners[$groupId] = $ownersResult.value
                }
            }
            catch {
                Write-Verbose "Could not fetch owners for group ${groupId}: $($_.Exception.Message)"
            }
        }
    }

    $groupCount = 0
    $totalGroups = $roleEnabledGroups.Count

    foreach ($groupId in $roleEnabledGroups) {
        $groupCount++
        if ($totalGroups -gt 0) {
            $percentComplete = [math]::Round(20 + ($groupCount / $totalGroups) * 30)
            Write-Progress -Activity "Analyzing escalation paths" -Status "Analyzing role-enabled group $groupCount of $totalGroups" -PercentComplete $percentComplete -Id 5
        }

        $group = $Groups | Where-Object { $_.id -eq $groupId }
        if (-not $group) { continue }

        $groupRoles = $RoleAssignments | Where-Object { $_.MemberId -eq $groupId }

        if ($groupRoles) {
            $memberCount = if ($groupMemberships.ContainsKey($groupId)) { $groupMemberships[$groupId].Count } else { 0 }
            $ownerCount = if ($groupOwners.ContainsKey($groupId)) { $groupOwners[$groupId].Count } else { 0 }

            foreach ($role in $groupRoles) {
                $risk = [PSCustomObject]@{
                    RiskType    = 'RoleEnabledGroup'
                    Severity    = 'High'
                    GroupId     = $group.id
                    GroupName   = $group.displayName
                    RoleName    = $role.RoleName
                    MemberCount = $memberCount
                    OwnerCount  = $ownerCount
                    Description = "Role-enabled group '$($group.displayName)' has '$($role.RoleName)' role with $memberCount members"
                }
                $escalationRisks += $risk
            }
        }
    }

    Write-Verbose "Analyzing nested group memberships..."

    $groupCount = 0
    $totalGroups = $groupsWithRoles.Count
    foreach ($groupId in $groupsWithRoles) {
        $groupCount++
        if ($totalGroups -gt 0) {
            $percentComplete = [math]::Round(50 + ($groupCount / $totalGroups) * 20)
            Write-Progress -Activity "Analyzing escalation paths" -Status "Analyzing nested memberships for group $groupCount of $totalGroups" -PercentComplete $percentComplete -Id 5
        }

        $group = $Groups | Where-Object { $_.id -eq $groupId }
        if ($group) {
            $directMemberCount = if ($groupMemberships.ContainsKey($groupId)) { $groupMemberships[$groupId].Count } else { 0 }
            $transitiveMemberCount = 0

            $transitiveResponseKey = $batchResponses.Keys | Where-Object { $_ -like "*-transitive-$groupId" } | Select-Object -First 1
            if ($transitiveResponseKey) {
                $transitiveResponse = $batchResponses[$transitiveResponseKey]
                if ($transitiveResponse -and $transitiveResponse.status -eq 200) {
                    $transitiveMemberCount = if ($transitiveResponse.body.'@odata.count') {
                        $transitiveResponse.body.'@odata.count'
                    }
                    else {
                        $transitiveResponse.body.value.Count
                    }
                }
            }
            else {
                try {
                    $transitiveUri = "$script:GraphBaseUrl/groups/$groupId/transitiveMembers?`$select=id&`$count=true"
                    $transitiveResult = Invoke-GraphRequest -Uri $transitiveUri -Method GET -ErrorAction SilentlyContinue
                    $transitiveMemberCount = if ($transitiveResult.'@odata.count') { $transitiveResult.'@odata.count' } else { $transitiveResult.value.Count }
                }
                catch {
                    Write-Verbose "Could not fetch transitive members for group ${groupId}: $($_.Exception.Message)"
                }
            }

            if ($transitiveMemberCount -gt $directMemberCount) {
                $nestedMemberCount = $transitiveMemberCount - $directMemberCount
                $groupRoles = $RoleAssignments | Where-Object { $_.MemberId -eq $groupId }

                foreach ($role in $groupRoles) {
                    $risk = [PSCustomObject]@{
                        RiskType      = 'NestedGroupMembership'
                        Severity      = 'Medium'
                        GroupId       = $group.id
                        GroupName     = $group.displayName
                        RoleName      = $role.RoleName
                        DirectMembers = $directMemberCount
                        NestedMembers = $nestedMemberCount
                        Description   = "Group '$($group.displayName)' with '$($role.RoleName)' has $nestedMemberCount members through nested groups"
                    }
                    $escalationRisks += $risk
                }
            }
        }
    }

    Write-Verbose "Analyzing service principal ownership..."
    Write-Progress -Activity "Analyzing escalation paths" -Status "Analyzing service principal ownership" -PercentComplete 70 -Id 5

    $spsWithRoles = $ServicePrincipals | Where-Object {
        $spId = $_.id
        $RoleAssignments | Where-Object { $_.MemberId -eq $spId }
    }

    $spBatchRequests = @()
    $spRequestId = 0
    foreach ($sp in $spsWithRoles) {
        $spBatchRequests += @{
            id     = "$spRequestId-sp-owners-$($sp.id)"
            method = "GET"
            url    = "/servicePrincipals/$($sp.id)/owners?`$select=id,displayName,userPrincipalName"
        }
        $spRequestId++

        $spBatchRequests += @{
            id     = "$spRequestId-sp-approles-$($sp.id)"
            method = "GET"
            url    = "/servicePrincipals/$($sp.id)/appRoleAssignedTo?`$select=principalId,principalDisplayName,principalType&`$top=100"
        }
        $spRequestId++
    }

    $spBatchResponses = @{}
    if ($spBatchRequests.Count -gt 0) {
        Write-Verbose "Fetching service principal data using batch requests ($($spBatchRequests.Count) requests)"
        try {
            $spBatchResponses = Invoke-GraphBatchRequest -Requests $spBatchRequests
        }
        catch {
            Write-Verbose "SP batch request failed, will use fallback: $_"
        }
    }

    $spCount = 0
    foreach ($sp in $spsWithRoles) {
        $ownerCount = 0

        $ownerResponseKey = $spBatchResponses.Keys | Where-Object { $_ -like "*-sp-owners-$($sp.id)" } | Select-Object -First 1
        if ($ownerResponseKey) {
            $ownerResponse = $spBatchResponses[$ownerResponseKey]
            if ($ownerResponse -and $ownerResponse.status -eq 200 -and $ownerResponse.body.value) {
                $spOwners[$sp.id] = $ownerResponse.body.value
                $ownerCount = $ownerResponse.body.value.Count
            }
        }
        else {
            try {
                $ownersUri = "$script:GraphBaseUrl/servicePrincipals/$($sp.id)/owners?`$select=id,displayName,userPrincipalName"
                $owners = Invoke-GraphRequest -Uri $ownersUri -Method GET -ErrorAction SilentlyContinue
                if ($owners.value) {
                    $spOwners[$sp.id] = $owners.value
                    $ownerCount = $owners.value.Count
                }
            }
            catch {
                Write-Verbose "Could not fetch owners for service principal $($sp.id): $_"
            }
        }

        $appRoleResponseKey = $spBatchResponses.Keys | Where-Object { $_ -like "*-sp-approles-$($sp.id)" } | Select-Object -First 1
        if ($appRoleResponseKey) {
            $appRoleResponse = $spBatchResponses[$appRoleResponseKey]
            if ($appRoleResponse -and $appRoleResponse.status -eq 200 -and $appRoleResponse.body.value) {
                $spAppRoleAssignments[$sp.id] = $appRoleResponse.body.value
            }
        }
        else {
            try {
                $appRolesUri = "$script:GraphBaseUrl/servicePrincipals/$($sp.id)/appRoleAssignedTo?`$select=principalId,principalDisplayName,principalType&`$top=100"
                $appRoles = Invoke-GraphRequest -Uri $appRolesUri -Method GET -ErrorAction SilentlyContinue
                if ($appRoles.value) {
                    $spAppRoleAssignments[$sp.id] = $appRoles.value
                }
            }
            catch {
                Write-Verbose "Could not fetch app role assignments for service principal $($sp.id): $_"
            }
        }

        if ($ownerCount -gt 0) {
            $spRoles = $RoleAssignments | Where-Object { $_.MemberId -eq $sp.id }

            foreach ($role in $spRoles) {
                $risk = [PSCustomObject]@{
                    RiskType             = 'ServicePrincipalOwnership'
                    Severity             = 'High'
                    ServicePrincipalId   = $sp.id
                    ServicePrincipalName = $sp.displayName
                    RoleName             = $role.RoleName
                    OwnerCount           = $ownerCount
                    Description          = "Service Principal '$($sp.displayName)' with '$($role.RoleName)' has $ownerCount owners who could potentially abuse permissions"
                }
                $escalationRisks += $risk
            }
        }
        $spCount++
    }

    if ($ServicePrincipals.Count -gt 0 -and $permissionEscalationLookup.Count -gt 0) {
        Write-Verbose "Analyzing workload identity API permissions for escalation risk..."

        foreach ($sp in $ServicePrincipals) {
            if (-not $sp.GrantedApplicationPermissions) { continue }

            $graphPermissions = $sp.GrantedApplicationPermissions | Where-Object {
                ($_.ResourceDisplayName -eq 'Microsoft Graph' -or $_.ResourceDisplayName -eq 'Microsoft Graph API' -or $_.ResourceId -eq '00000003-0000-0000-c000-000000000000') -and $_.AppRoleValue
            }

            foreach ($grant in $graphPermissions) {
                $permValue = $grant.AppRoleValue
                if (-not $permValue) { continue }

                if ($permissionEscalationLookup.ContainsKey($permValue)) {
                    $metadata = $permissionEscalationLookup[$permValue]

                    $risk = [PSCustomObject]@{
                        RiskType             = 'AppPermissionEscalation'
                        Severity             = $metadata.Severity
                        ServicePrincipalId   = $sp.id
                        ServicePrincipalName = $sp.displayName
                        Permission           = $permValue
                        AttackPath           = $metadata.AttackPath
                        Recommendation       = $metadata.Recommendation
                        Reference            = $metadata.Reference
                        Description          = "Service Principal '$($sp.displayName)' has Microsoft Graph permission '$permValue' which $($metadata.AttackPath.ToLower())"
                    }
                    $escalationRisks += $risk
                }
            }
        }
    }

    Write-Verbose "Analyzing app registration ownership..."
    Write-Progress -Activity "Analyzing escalation paths" -Status "Analyzing app registration ownership" -PercentComplete 85 -Id 5

    $appBatchRequests = @()
    $appRequestId = 0
    foreach ($app in $AppRegistrations) {
        $appBatchRequests += @{
            id     = "$appRequestId-app-$($app.id)"
            method = "GET"
            url    = "/applications/$($app.id)/owners?`$select=id,displayName,userPrincipalName"
        }
        $appRequestId++
    }

    $appBatchResponses = @{}
    if ($appBatchRequests.Count -gt 0) {
        Write-Verbose "Fetching app registration owners using batch requests ($($appBatchRequests.Count) requests)"
        try {
            $appBatchResponses = Invoke-GraphBatchRequest -Requests $appBatchRequests
        }
        catch {
            Write-Verbose "App batch request failed, will use fallback: $_"
        }
    }

    $appCount = 0
    foreach ($app in $AppRegistrations) {
        $ownerCount = 0

        $ownerResponseKey = $appBatchResponses.Keys | Where-Object { $_ -like "*-app-$($app.id)" } | Select-Object -First 1
        if ($ownerResponseKey) {
            $ownerResponse = $appBatchResponses[$ownerResponseKey]
            if ($ownerResponse -and $ownerResponse.status -eq 200 -and $ownerResponse.body.value) {
                $appOwners[$app.id] = $ownerResponse.body.value
                $ownerCount = $ownerResponse.body.value.Count
            }
        }
        else {
            try {
                $ownersUri = "$script:GraphBaseUrl/applications/$($app.id)/owners?`$select=id,displayName,userPrincipalName"
                $owners = Invoke-GraphRequest -Uri $ownersUri -Method GET -ErrorAction SilentlyContinue
                if ($owners.value) {
                    $appOwners[$app.id] = $owners.value
                    $ownerCount = $owners.value.Count
                }
            }
            catch {
                Write-Verbose "Could not analyze app registration $($app.id): $_"
            }
        }

        if ($ownerCount -gt 5) {
            $risk = [PSCustomObject]@{
                RiskType    = 'AppRegistrationOwnership'
                Severity    = 'Medium'
                AppId       = $app.id
                AppName     = $app.displayName
                OwnerCount  = $ownerCount
                Description = "App Registration '$($app.displayName)' has $ownerCount owners - potential for credential abuse"
            }
            $escalationRisks += $risk
        }
        $appCount++
    }

    Write-Progress -Activity "Analyzing escalation paths" -Completed -Id 5

    Write-Verbose "Analyzing administrative roles with escalation capabilities..."

    $appManagementRoles = @(
        'Cloud Application Administrator',
        'Application Administrator',
        'Hybrid Identity Administrator'
    )

    $roleManagementRoles = @(
        'Privileged Role Administrator',
        'Global Administrator'
    )

    $appAdminAssignments = $RoleAssignments | Where-Object { $appManagementRoles -contains $_.RoleName }
    $appAdminPIMAssignments = $PIMAssignments | Where-Object { $appManagementRoles -contains $_.RoleName }

    foreach ($assignment in ($appAdminAssignments + $appAdminPIMAssignments)) {
        $privilegedSPs = $ServicePrincipals | Where-Object {
            $spId = $_.id
            ($RoleAssignments | Where-Object { $_.MemberId -eq $spId }).Count -gt 0
        }

        if ($privilegedSPs.Count -gt 0) {
            $isPIM = $assignment -in $appAdminPIMAssignments
            $risk = [PSCustomObject]@{
                RiskType          = 'AppAdministratorEscalation'
                Severity          = 'High'
                PrincipalId       = $assignment.MemberId
                PrincipalType     = $assignment.MemberType
                RoleName          = $assignment.RoleName
                PrivilegedSPCount = $privilegedSPs.Count
                IsPIM             = $isPIM
                Description       = "$(if($isPIM){'PIM eligible '})$($assignment.RoleName) can manage $($privilegedSPs.Count) service principal(s) with privileged role assignments, enabling potential privilege escalation"
            }
            $escalationRisks += $risk
        }
    }

    $roleAdminAssignments = $RoleAssignments | Where-Object { $roleManagementRoles -contains $_.RoleName }
    $roleAdminPIMAssignments = $PIMAssignments | Where-Object { $roleManagementRoles -contains $_.RoleName }

    foreach ($assignment in ($roleAdminAssignments + $roleAdminPIMAssignments)) {
        $isPIM = $assignment -in $roleAdminPIMAssignments

        $risk = [PSCustomObject]@{
            RiskType      = 'RoleAdministratorEscalation'
            Severity      = 'Critical'
            PrincipalId   = $assignment.MemberId
            PrincipalType = $assignment.MemberType
            RoleName      = $assignment.RoleName
            IsPIM         = $isPIM
            Description   = "$(if($isPIM){'PIM eligible '})$($assignment.RoleName) can assign any role including Global Administrator, representing maximum escalation risk"
        }
        $escalationRisks += $risk
    }

    if ($PIMAssignments.Count -gt 0) {
        Write-Verbose "Analyzing PIM assignment patterns..."
        Write-Progress -Activity "Analyzing PIM assignment patterns" -Status "Grouping PIM assignments by principal" -PercentComplete 50 -Id 9

        $pimByPrincipal = $PIMAssignments | Group-Object -Property PrincipalId

        foreach ($principalGroup in $pimByPrincipal) {
            if ($principalGroup.Count -gt 3) {
                $risk = [PSCustomObject]@{
                    RiskType     = 'MultiplePIMRoles'
                    Severity     = 'Medium'
                    PrincipalId  = $principalGroup.Name
                    PIMRoleCount = $principalGroup.Count
                    Roles        = ($principalGroup.Group | Select-Object -ExpandProperty RoleName) -join ', '
                    Description  = "Principal has $($principalGroup.Count) PIM role assignments: $($principalGroup.Group | Select-Object -ExpandProperty RoleName -First 3 | Join-String -Separator ', ')..."
                }
                $escalationRisks += $risk
            }
        }

        Write-Progress -Activity "Analyzing PIM assignment patterns" -Completed -Id 9
    }

    Write-Host "Identified $($escalationRisks.Count) potential escalation risks" -ForegroundColor Yellow

    Write-Verbose "Building graph data structure for visualization..."
    Write-Progress -Activity "Analyzing escalation paths" -Status "Building graph visualization data" -PercentComplete 95 -Id 5

    $allRoleAssignments = @($RoleAssignments; $PIMAssignments)

    $graphData = New-ScEntraGraphData `
        -Users $Users `
        -Groups $Groups `
        -ServicePrincipals $ServicePrincipals `
        -AppRegistrations $AppRegistrations `
        -RoleAssignments $RoleAssignments `
        -PIMAssignments $PIMAssignments `
        -GroupMemberships $groupMemberships `
        -GroupOwners $groupOwners `
        -SPOwners $spOwners `
        -SPAppRoleAssignments $spAppRoleAssignments `
        -AppOwners $appOwners

    Write-Progress -Activity "Analyzing escalation paths" -Completed -Id 5

    return @{
        Risks     = $escalationRisks
        GraphData = $graphData
    }
}
