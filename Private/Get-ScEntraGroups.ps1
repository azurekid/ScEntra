function Get-ScEntraGroups {
    <#
    .SYNOPSIS
        Gets all groups from Entra ID

    .DESCRIPTION
        Retrieves comprehensive information about all groups including role-enabled status.
        Member counts are fetched on-demand only for groups relevant to role analysis.

    .EXAMPLE
        $groups = Get-ScEntraGroups
    #>
    [CmdletBinding()]
    param()

    if (-not (Test-GraphConnection)) {
        return
    }

    Write-Verbose "Retrieving all groups from Entra ID..."

    try {
        $select = "id,displayName,description,groupTypes,securityEnabled,mailEnabled,isAssignableToRole,createdDateTime,membershipRule,membershipRuleProcessingState"
        $uri = "$script:GraphBaseUrl/groups?`$top=999&`$select=$select"

        $groups = Get-AllGraphItems -Uri $uri -ProgressActivity "Retrieving groups from Entra ID"

        # PIM enablement is independent from the isAssignableToRole flag (see https://learn.microsoft.com/entra/id-governance/privileged-identity-management/concept-pim-for-groups#relationship-between-role-assignable-groups-and-pim-for-groups)
        # Note: We discover PIM-enabled groups indirectly by checking each group's PIM role assignments endpoint
        # The privilegedAccess schedule list endpoints require groupId/principalId filters and cannot enumerate all groups
        $pimEnabledGroupIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        
        # Query PIM role assignments to discover which groups are PIM-enabled
        # This endpoint returns assignments where groups are assigned to directory roles via PIM
        try {
            $pimRoleAssignments = Get-AllGraphItems -Uri "$script:GraphBaseUrl/roleManagement/directory/roleEligibilityScheduleInstances?`$expand=principal" -ProgressActivity "Discovering PIM-enabled groups via role assignments"
            if ($pimRoleAssignments) {
                foreach ($assignment in $pimRoleAssignments) {
                    if ($assignment.principal.'@odata.type' -eq '#microsoft.graph.group' -and $assignment.principal.id) {
                        $null = $pimEnabledGroupIds.Add($assignment.principal.id)
                    }
                }
            }
        }
        catch {
            Write-Verbose "Unable to retrieve PIM role assignments for group discovery: $_"
        }

        foreach ($group in $groups) {
            $group | Add-Member -NotePropertyName 'isPIMEnabled' -NotePropertyValue ($pimEnabledGroupIds.Contains($group.id)) -Force
        }

        if ($pimEnabledGroupIds.Count -gt 0) {
            Write-Host "Detected $($pimEnabledGroupIds.Count) PIM-enabled groups via role eligibility schedules" -ForegroundColor Yellow
        }
        else {
            Write-Verbose "No groups with PIM role eligibility were found."
        }

        Write-Host "Retrieved $($groups.Count) groups" -ForegroundColor Green
        Write-Verbose "Member counts will be fetched on-demand for groups with role assignments or PIM eligibility"

        return $groups
    }
    catch {
        Write-Error "Error retrieving groups: $_"
        return @()
    }
}
