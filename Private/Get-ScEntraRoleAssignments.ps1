function Get-ScEntraRoleAssignments {
    <#
    .SYNOPSIS
        Gets all directory role assignments

    .DESCRIPTION
        Retrieves all direct role assignments in Entra ID

    .EXAMPLE
        $roleAssignments = Get-ScEntraRoleAssignments
    #>
    [CmdletBinding()]
    param()

    if (-not (Test-GraphConnection)) {
        return @()
    }

    # Check required permissions
    $requiredPermissions = @('RoleManagement.Read.Directory')
    if (-not (Test-GraphPermissions -RequiredPermissions $requiredPermissions -ResourceName "Role Assignments")) {
        Write-Warning "Cannot retrieve role assignments without required permissions."
        return @()
    }

    Write-Verbose "Retrieving directory role assignments..."

    try {
        $rolesUri = "$script:GraphBaseUrl/directoryRoles?`$select=id,displayName,description,roleTemplateId"
        $roles = Get-AllGraphItems -Uri $rolesUri -ProgressActivity "Retrieving directory roles"

        $roleDefinitionLookup = @{}
        try {
            $definitionsUri = "$script:GraphBaseUrl/roleManagement/directory/roleDefinitions?`$select=id,displayName,description,isBuiltIn,isEnabled,templateId,resourceScopes,rolePermissions"
            $roleDefinitions = Get-AllGraphItems -Uri $definitionsUri -ProgressActivity "Retrieving role definitions"
            foreach ($definition in $roleDefinitions) {
                if ($definition.templateId) {
                    $roleDefinitionLookup[$definition.templateId] = $definition
                }
            }
        }
        catch {
            Write-Verbose "Unable to retrieve role definitions for metadata enrichment: $_"
        }

        $allAssignments = @()
        $roleCount = 0
        $totalRoles = $roles.Count

        foreach ($role in $roles) {
            $roleCount++
            $percentComplete = [math]::Round(($roleCount / $totalRoles) * 100)
            Write-Progress -Activity "Enumerating role assignments" -Status "Processing role $roleCount of $totalRoles - $($role.displayName)" -PercentComplete $percentComplete -Id 3
            Write-Verbose "Processing role: $($role.displayName)"

            $roleDefinition = $null
            if ($role.PSObject.Properties.Name -contains 'roleTemplateId' -and $role.roleTemplateId -and $roleDefinitionLookup.ContainsKey($role.roleTemplateId)) {
                $roleDefinition = $roleDefinitionLookup[$role.roleTemplateId]
            }

            $roleDescription = if ($role.description) {
                $role.description
            }
            elseif ($roleDefinition -and $roleDefinition.description) {
                $roleDefinition.description
            }
            else {
                $null
            }

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
            $allowedActionsCount = $allowedActions.Count

            $membersUri = "$script:GraphBaseUrl/directoryRoles/$($role.id)/members?`$select=id"
            $members = Get-AllGraphItems -Uri $membersUri

            foreach ($member in $members) {
                $assignment = [PSCustomObject]@{
                    RoleId = $role.id
                    RoleName = $role.displayName
                    RoleDescription = $roleDescription
                    RoleDefinitionId = if ($roleDefinition) { $roleDefinition.id } else { $null }
                    RoleTemplateId = if ($role.PSObject.Properties.Name -contains 'roleTemplateId') { $role.roleTemplateId } else { $null }
                    RoleIsBuiltIn = if ($roleDefinition -and ($roleDefinition.PSObject.Properties.Name -contains 'isBuiltIn')) { [bool]$roleDefinition.isBuiltIn } else { $null }
                    RoleIsEnabled = if ($roleDefinition -and ($roleDefinition.PSObject.Properties.Name -contains 'isEnabled')) { [bool]$roleDefinition.isEnabled } else { $null }
                    RoleResourceScopes = $resourceScopes
                    RoleAllowedActions = $allowedActions
                    RoleAllowedActionsCount = $allowedActionsCount
                    MemberId = $member.id
                    MemberType = if ($member.'@odata.type') {
                        $member.'@odata.type' -replace '#microsoft.graph.', ''
                    } else {
                        'unknown'
                    }
                    AssignmentType = 'Direct'
                }
                $allAssignments += $assignment
            }
        }

        Write-Progress -Activity "Enumerating role assignments" -Completed -Id 3

        Write-Host "Retrieved $($allAssignments.Count) direct role assignments across $($roles.Count) roles" -ForegroundColor Green
        return $allAssignments
    }
    catch {
        Write-Error "Error retrieving role assignments: $_"
        return @()
    }
}
