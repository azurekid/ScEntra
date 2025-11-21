function Get-ScEntraAppRegistrations {
    <#
    .SYNOPSIS
        Gets all app registrations from Entra ID

    .DESCRIPTION
        Retrieves comprehensive information about all application registrations

    .EXAMPLE
        $apps = Get-ScEntraAppRegistrations
    #>
    [CmdletBinding()]
    param()

    if (-not (Test-GraphConnection)) { return @() }

    # Check required permissions
    $requiredPermissions = @('Application.Read.All')
    if (-not (Test-GraphPermissions -RequiredPermissions $requiredPermissions -ResourceName "App Registrations")) {
        Write-Warning "Cannot retrieve app registrations without required permissions."
        return @()
    }

    $select = "id,displayName,appId,createdDateTime,signInAudience,publisherDomain"
    $uri = "$script:GraphBaseUrl/applications?`$top=999&`$select=$select"

    try {
        $apps = Get-AllGraphItems -Uri $uri -ProgressActivity "Retrieving app registrations from Entra ID"
        Write-Host "Retrieved $($apps.Count) app registrations" -ForegroundColor Green
        return $apps
    }
    catch {
        Write-Error "Error retrieving app registrations: $_"
        return @()
    }
}
