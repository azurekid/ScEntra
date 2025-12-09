function Get-ScEntraPIMAssignments {
    <#
    .SYNOPSIS
        Gets all PIM (Privileged Identity Management) role assignments

    .DESCRIPTION
        Retrieves both active and eligible PIM role assignments

    .EXAMPLE
        $pimAssignments = Get-ScEntraPIMAssignments
    #>
    [CmdletBinding()]
    param()

    if (-not (Test-GraphConnection)) { return @() }

    # Check required permissions
    $requiredPermissions = @('RoleEligibilitySchedule.Read.Directory', 'RoleAssignmentSchedule.Read.Directory')
    if (-not (Test-GraphPermissions -RequiredPermissions $requiredPermissions -ResourceName "PIM Assignments")) {
        Write-Warning "Cannot retrieve PIM assignments without required permissions. PIM-eligible users/groups will not appear in the graph."
        return @()
    }

    # Helper function to convert schedule to assignment object
    function ConvertTo-PIMAssignment {
        param($Schedule, $AssignmentType)
        
        $roleDefinition = $Schedule.roleDefinition

        $roleDescription = if ($roleDefinition -and $roleDefinition.description) { $roleDefinition.description } else { $null }
        $resourceScopes = @()
        if ($roleDefinition -and $roleDefinition.resourceScopes) {
            $resourceScopes = @($roleDefinition.resourceScopes | Sort-Object -Unique)
        }

        $allowedActions = @()
        if ($roleDefinition -and $roleDefinition.rolePermissions) {
            foreach ($permission in $roleDefinition.rolePermissions) {
                if ($permission.allowedResourceActions) {
                    $allowedActions += $permission.allowedResourceActions
                }
            }
            if ($allowedActions.Count -gt 0) {
                $allowedActions = $allowedActions | Sort-Object -Unique
            }
        }

        [PSCustomObject]@{
            AssignmentId = $Schedule.id
            RoleId = $Schedule.roleDefinitionId
            RoleDefinitionId = if ($roleDefinition) { $roleDefinition.id } else { $Schedule.roleDefinitionId }
            RoleTemplateId = if ($roleDefinition -and ($roleDefinition.PSObject.Properties.Name -contains 'templateId')) { $roleDefinition.templateId } else { $null }
            RoleName = if ($roleDefinition) { $roleDefinition.displayName } elseif ($Schedule.roleDefinition) { $Schedule.roleDefinition.displayName } else { 'Unknown' }
            RoleDescription = $roleDescription
            RoleIsBuiltIn = if ($roleDefinition -and ($roleDefinition.PSObject.Properties.Name -contains 'isBuiltIn')) { [bool]$roleDefinition.isBuiltIn } else { $null }
            RoleIsEnabled = if ($roleDefinition -and ($roleDefinition.PSObject.Properties.Name -contains 'isEnabled')) { [bool]$roleDefinition.isEnabled } else { $null }
            RoleResourceScopes = $resourceScopes
            RoleAllowedActions = $allowedActions
            RoleAllowedActionsCount = $allowedActions.Count
            PrincipalId = $Schedule.principalId
            PrincipalDisplayName = if ($Schedule.principal) { $Schedule.principal.displayName } else { 'Unknown' }
            PrincipalType = if ($Schedule.principal -and $Schedule.principal.'@odata.type') {
                $Schedule.principal.'@odata.type' -replace '#microsoft.graph.', ''
            } else {
                'unknown'
            }
            AssignmentType = $AssignmentType
            Status = $Schedule.status
            CreatedDateTime = $Schedule.createdDateTime
        }
    }

    $allPIMAssignments = @()

    try {
        # Fetch eligible assignments
        Write-Progress -Activity "Retrieving PIM assignments" -Status "Fetching eligible role assignments" -PercentComplete 25 -Id 4
        try {
            $eligibleUri = "$script:GraphBaseUrl/roleManagement/directory/roleEligibilitySchedules?`$expand=principal,roleDefinition"
            $eligibleSchedules = Get-AllGraphItems -Uri $eligibleUri -ErrorAction SilentlyContinue
            $allPIMAssignments += $eligibleSchedules | ForEach-Object { ConvertTo-PIMAssignment -Schedule $_ -AssignmentType 'PIM-Eligible' }
        }
        catch {
            Write-Verbose "Could not retrieve PIM eligible assignments: $_"
        }

        # Fetch active assignments
        Write-Progress -Activity "Retrieving PIM assignments" -Status "Fetching active role assignments" -PercentComplete 75 -Id 4
        try {
            $activeUri = "$script:GraphBaseUrl/roleManagement/directory/roleAssignmentSchedules?`$expand=principal,roleDefinition"
            $activeSchedules = Get-AllGraphItems -Uri $activeUri -ErrorAction SilentlyContinue
            $allPIMAssignments += $activeSchedules | ForEach-Object { ConvertTo-PIMAssignment -Schedule $_ -AssignmentType 'PIM-Active' }
        }
        catch {
            Write-Verbose "Could not retrieve PIM active assignments: $_"
        }

        Write-Progress -Activity "Retrieving PIM assignments" -Completed -Id 4

        $eligibleCount = ($allPIMAssignments | Where-Object { $_.AssignmentType -eq 'PIM-Eligible' }).Count
        $activeCount = ($allPIMAssignments | Where-Object { $_.AssignmentType -eq 'PIM-Active' }).Count
        
        Write-Host "Retrieved $($allPIMAssignments.Count) PIM assignments ($eligibleCount eligible, $activeCount active)" -ForegroundColor Green
        return $allPIMAssignments
    }
    catch {
        Write-Error "Error retrieving PIM assignments: $_"
        return @()
    }
}
