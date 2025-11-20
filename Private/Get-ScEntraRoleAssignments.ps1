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
        return
    }

    Write-Verbose "Retrieving directory role assignments..."

    try {
        $rolesUri = "$script:GraphBaseUrl/directoryRoles?`$select=id,displayName,description"
        $roles = Get-AllGraphItems -Uri $rolesUri -ProgressActivity "Retrieving directory roles"

        $allAssignments = @()
        $roleCount = 0
        $totalRoles = $roles.Count

        foreach ($role in $roles) {
            $roleCount++
            $percentComplete = [math]::Round(($roleCount / $totalRoles) * 100)
            Write-Progress -Activity "Enumerating role assignments" -Status "Processing role $roleCount of $totalRoles - $($role.displayName)" -PercentComplete $percentComplete -Id 3
            Write-Verbose "Processing role: $($role.displayName)"

            $membersUri = "$script:GraphBaseUrl/directoryRoles/$($role.id)/members?`$select=id"
            $members = Get-AllGraphItems -Uri $membersUri

            foreach ($member in $members) {
                $assignment = [PSCustomObject]@{
                    RoleId = $role.id
                    RoleName = $role.displayName
                    RoleDescription = $role.description
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
