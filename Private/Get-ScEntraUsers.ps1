function Get-ScEntraUsers {
    <#
    .SYNOPSIS
        Gets all users from Entra ID

    .DESCRIPTION
        Retrieves comprehensive information about all users in the Entra ID tenant

    .EXAMPLE
        $users = Get-ScEntraUsers
    #>
    [CmdletBinding()]
    param()

    if (-not (Test-GraphConnection)) {
        return
    }

    Write-Verbose "Retrieving all users from Entra ID..."

    try {
        $select = "id,displayName,userPrincipalName,mail,accountEnabled,createdDateTime,userType,onPremisesSyncEnabled"
        $uri = "$script:GraphBaseUrl/users?`$top=999&`$select=$select"

        $users = Get-AllGraphItems -Uri $uri -ProgressActivity "Retrieving users from Entra ID"

        Write-Host "Retrieved $($users.Count) users" -ForegroundColor Green
        return $users
    }
    catch {
        Write-Error "Error retrieving users: $_"
        return @()
    }
}
