function Get-ScEntraServicePrincipals {
    <#
    .SYNOPSIS
        Gets all service principals from Entra ID

    .DESCRIPTION
        Retrieves comprehensive information about all service principals

    .EXAMPLE
        $servicePrincipals = Get-ScEntraServicePrincipals
    #>
    [CmdletBinding()]
    param()

    if (-not (Test-GraphConnection)) {
        return
    }

    Write-Verbose "Retrieving all service principals from Entra ID..."

    try {
        $select = "id,displayName,appId,servicePrincipalType,accountEnabled,createdDateTime,appOwnerOrganizationId"
        $uri = "$script:GraphBaseUrl/servicePrincipals?`$top=999&`$select=$select"

        $servicePrincipals = Get-AllGraphItems -Uri $uri -ProgressActivity "Retrieving service principals from Entra ID"

        Write-Host "Retrieved $($servicePrincipals.Count) service principals" -ForegroundColor Green
        return $servicePrincipals
    }
    catch {
        Write-Error "Error retrieving service principals: $_"
        return @()
    }
}
