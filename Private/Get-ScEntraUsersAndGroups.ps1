function Get-ScEntraUsersAndGroups {
    <#
    .SYNOPSIS
        Gets all users and groups from Entra ID

    .DESCRIPTION
        Efficiently retrieves comprehensive information about users and groups in a single operation.
        Groups are enriched with PIM-enabled status information.

    .EXAMPLE
        $result = Get-ScEntraUsersAndGroups
        $users = $result.Users
        $groups = $result.Groups
    #>
    [CmdletBinding()]
    param()

    if (-not (Test-GraphConnection)) { 
        return @{
            Users = @()
            Groups = @()
        }
    }

    # Check required permissions
    $requiredPermissions = @('User.Read.All', 'Group.Read.All', 'RoleEligibilitySchedule.Read.Directory')
    if (-not (Test-GraphPermissions -RequiredPermissions $requiredPermissions -ResourceName "Users and Groups")) {
        Write-Warning "Some data may be incomplete due to missing permissions."
    }

    $result = @{
        Users = @()
        Groups = @()
    }

    try {
        # Fetch users
        $userSelect = "id,displayName,userPrincipalName,mail,accountEnabled,createdDateTime,userType,onPremisesSyncEnabled,lastPasswordChangeDateTime,signInSessionsValidFromDateTime"
        $userUri = "$script:GraphBaseUrl/users?`$top=999&`$select=$userSelect"
        $result.Users = Get-AllGraphItems -Uri $userUri -ProgressActivity "Retrieving users from Entra ID"
        Write-Host "Retrieved $($result.Users.Count) users" -ForegroundColor Green

        # Fetch groups
        $groupSelect = "id,displayName,description,groupTypes,securityEnabled,mailEnabled,isAssignableToRole,createdDateTime,membershipRule,membershipRuleProcessingState"
        $groupUri = "$script:GraphBaseUrl/groups?`$top=999&`$select=$groupSelect"
        $result.Groups = Get-AllGraphItems -Uri $groupUri -ProgressActivity "Retrieving groups from Entra ID"

        # Discover PIM-enabled groups via role eligibility schedules
        # PIM enablement is independent from the isAssignableToRole flag
        # (see https://learn.microsoft.com/entra/id-governance/privileged-identity-management/concept-pim-for-groups#relationship-between-role-assignable-groups-and-pim-for-groups)
        $pimEnabledGroupIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        
        try {
            $pimRoleAssignments = Get-AllGraphItems -Uri "$script:GraphBaseUrl/roleManagement/directory/roleEligibilityScheduleInstances?`$expand=principal" -ProgressActivity "Discovering PIM-enabled groups via role assignments"
            
            $pimRoleAssignments | Where-Object { $_.principal.'@odata.type' -eq '#microsoft.graph.group' -and $_.principal.id } | 
                ForEach-Object { $null = $pimEnabledGroupIds.Add($_.principal.id) }
        }
        catch {
            Write-Verbose "Unable to retrieve PIM role assignments for group discovery: $_"
        }

        # Add PIM status to groups
        $result.Groups | ForEach-Object {
            $_ | Add-Member -NotePropertyName 'isPIMEnabled' -NotePropertyValue ($pimEnabledGroupIds.Contains($_.id)) -Force
        }

        if ($pimEnabledGroupIds.Count -gt 0) {
            Write-Host "Detected $($pimEnabledGroupIds.Count) PIM-enabled groups via role eligibility schedules" -ForegroundColor Yellow
        }

        Write-Host "Retrieved $($result.Groups.Count) groups" -ForegroundColor Green
        return $result
    }
    catch {
        Write-Error "Error retrieving users and groups: $_"
        return @{
            Users = @()
            Groups = @()
        }
    }
}
