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

    if (-not (Test-GraphConnection)) {
        return
    }

    Write-Verbose "Retrieving PIM role assignments..."

    try {
        $eligibleAssignments = @()
        try {
            Write-Progress -Activity "Retrieving PIM assignments" -Status "Fetching eligible role assignments" -PercentComplete 25 -Id 4
            $eligibleUri = "$script:GraphBaseUrl/roleManagement/directory/roleEligibilitySchedules?`$expand=principal,roleDefinition"
            $eligibleSchedules = Get-AllGraphItems -Uri $eligibleUri -ErrorAction SilentlyContinue

            foreach ($schedule in $eligibleSchedules) {
                $assignment = [PSCustomObject]@{
                    AssignmentId = $schedule.id
                    RoleId = $schedule.roleDefinitionId
                    RoleName = if ($schedule.roleDefinition) { $schedule.roleDefinition.displayName } else { 'Unknown' }
                    PrincipalId = $schedule.principalId
                    PrincipalDisplayName = if ($schedule.principal) { $schedule.principal.displayName } else { 'Unknown' }
                    PrincipalType = if ($schedule.principal -and $schedule.principal.'@odata.type') {
                        $schedule.principal.'@odata.type' -replace '#microsoft.graph.', ''
                    } else {
                        'unknown'
                    }
                    AssignmentType = 'PIM-Eligible'
                    Status = $schedule.status
                    CreatedDateTime = $schedule.createdDateTime
                }
                $eligibleAssignments += $assignment
            }
        }
        catch {
            Write-Verbose "Could not retrieve PIM eligible assignments: $_"
        }

        $activeAssignments = @()
        try {
            Write-Progress -Activity "Retrieving PIM assignments" -Status "Fetching active role assignments" -PercentComplete 75 -Id 4
            $activeUri = "$script:GraphBaseUrl/roleManagement/directory/roleAssignmentSchedules?`$expand=principal,roleDefinition"
            $activeSchedules = Get-AllGraphItems -Uri $activeUri -ErrorAction SilentlyContinue

            foreach ($schedule in $activeSchedules) {
                $assignment = [PSCustomObject]@{
                    AssignmentId = $schedule.id
                    RoleId = $schedule.roleDefinitionId
                    RoleName = if ($schedule.roleDefinition) { $schedule.roleDefinition.displayName } else { 'Unknown' }
                    PrincipalId = $schedule.principalId
                    PrincipalDisplayName = if ($schedule.principal) { $schedule.principal.displayName } else { 'Unknown' }
                    PrincipalType = if ($schedule.principal -and $schedule.principal.'@odata.type') {
                        $schedule.principal.'@odata.type' -replace '#microsoft.graph.', ''
                    } else {
                        'unknown'
                    }
                    AssignmentType = 'PIM-Active'
                    Status = $schedule.status
                    CreatedDateTime = $schedule.createdDateTime
                }
                $activeAssignments += $assignment
            }
        }
        catch {
            Write-Verbose "Could not retrieve PIM active assignments: $_"
        }

        Write-Progress -Activity "Retrieving PIM assignments" -Completed -Id 4

        $allPIMAssignments = $eligibleAssignments + $activeAssignments

        Write-Host "Retrieved $($allPIMAssignments.Count) PIM assignments ($($eligibleAssignments.Count) eligible, $($activeAssignments.Count) active)" -ForegroundColor Green
        return $allPIMAssignments
    }
    catch {
        Write-Error "Error retrieving PIM assignments: $_"
        return @()
    }
}
