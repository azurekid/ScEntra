function Connect-ScEntraGraph {
    <#
    .SYNOPSIS
        Connects to Microsoft Graph API and obtains an access token

    .DESCRIPTION
        Authenticates to Microsoft Graph using device code flow or existing access token

    .PARAMETER AccessToken
        Existing access token to use for authentication

    .PARAMETER Scopes
        Array of permission scopes required

    .PARAMETER TenantId
        The tenant ID to authenticate against

    .EXAMPLE
        Connect-ScEntraGraph -Scopes "User.Read.All", "Group.Read.All"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$AccessToken,

        [Parameter(Mandatory = $false)]
        [switch]$UseDeviceCode,

        [Parameter(Mandatory = $false)]
        [string[]]$Scopes = @(
            "User.Read.All",
            "Group.Read.All",
            "Application.Read.All",
            "RoleManagement.Read.Directory",
            "RoleEligibilitySchedule.Read.Directory",
            "RoleAssignmentSchedule.Read.Directory",
            "PrivilegedAccess.Read.AzureADGroup",
            "DelegatedPermissionGrant.Read.All"
        ),

        [Parameter(Mandatory = $false)]
        [string]$TenantId = "common"
    )

    # Use Device Code Flow if requested
    if ($UseDeviceCode) {
        Write-Host "`nInitiating OAuth2 Device Code Flow..." -ForegroundColor Cyan
        
        # Microsoft Graph PowerShell public client ID (supports custom scopes)
        $clientId = "14d82eec-204b-4c2f-b7e8-296a70dab67e"
        $scopeString = ($Scopes | ForEach-Object { "https://graph.microsoft.com/$_" }) -join " "
        
        # Request device code
        $deviceCodeRequest = @{
            Uri     = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/devicecode"
            Method  = 'POST'
            Body    = @{
                client_id = $clientId
                scope     = $scopeString
            }
        }
        
        try {
            $deviceCodeResponse = Invoke-RestMethod @deviceCodeRequest
            
            Write-Host "`n$($deviceCodeResponse.message)" -ForegroundColor Yellow
            Write-Host "`nWaiting for authentication..." -ForegroundColor Cyan
            
            # Poll for token
            $tokenRequest = @{
                Uri    = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
                Method = 'POST'
            }
            
            $interval = if ($deviceCodeResponse.interval) { $deviceCodeResponse.interval } else { 5 }
            $expiresAt = (Get-Date).AddSeconds($deviceCodeResponse.expires_in)
            
            while ((Get-Date) -lt $expiresAt) {
                Start-Sleep -Seconds $interval
                
                $tokenRequest['Body'] = @{
                    grant_type  = 'urn:ietf:params:oauth:grant-type:device_code'
                    client_id   = $clientId
                    device_code = $deviceCodeResponse.device_code
                }
                
                try {
                    $tokenResponse = Invoke-RestMethod @tokenRequest -ErrorAction Stop
                    $script:GraphAccessToken = $tokenResponse.access_token
                    Write-Host "`n✓ Successfully authenticated with device code flow!" -ForegroundColor Green
                    
                    # Validate permissions
                    $missingScopes = @()
                    foreach ($scope in $Scopes) {
                        if (-not (Test-GraphPermissions -RequiredPermissions @($scope) -ResourceName "Device code token")) {
                            $missingScopes += $scope
                        }
                    }
                    
                    if ($missingScopes.Count -gt 0) {
                        Write-Warning "Token is missing some permissions (may need admin consent):"
                        $missingScopes | ForEach-Object { Write-Warning "  - $_" }
                    }
                    
                    return $true
                }
                catch {
                    $errorResponse = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
                    if ($errorResponse.error -eq 'authorization_pending') {
                        # Still waiting for user to authenticate
                        continue
                    }
                    elseif ($errorResponse.error -eq 'authorization_declined') {
                        Write-Error "Authentication was declined by the user"
                        return $false
                    }
                    elseif ($errorResponse.error -eq 'expired_token') {
                        Write-Error "Device code expired. Please try again."
                        return $false
                    }
                    else {
                        throw
                    }
                }
            }
            
            Write-Error "Device code expired. Please try again."
            return $false
        }
        catch {
            Write-Error "Device code flow failed: $_"
            return $false
        }
    }

    if ($AccessToken) {
        $script:GraphAccessToken = $AccessToken
        Write-Verbose "Using provided access token"
        
        # Validate the token has required permissions
        $missingScopes = @()
        foreach ($scope in $Scopes) {
            if (-not (Test-GraphPermissions -RequiredPermissions @($scope) -ResourceName "Initial validation")) {
                $missingScopes += $scope
            }
        }
        
        if ($missingScopes.Count -gt 0) {
            Write-Warning "Provided access token is missing required permissions:"
            $missingScopes | ForEach-Object { Write-Warning "  - $_" }
            Write-Host "`nYou can continue, but some functionality may not work." -ForegroundColor Yellow
        }
        else {
            Write-Host "✓ Access token validated with all required permissions" -ForegroundColor Green
        }
        
        return $true
    }

    try {
        $azContext = Get-AzContext -ErrorAction SilentlyContinue
        if ($azContext) {
            $token = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com" -ErrorAction SilentlyContinue
            if ($token) {
                $script:GraphAccessToken = $token.Token | ConvertFrom-SecureString -AsPlainText
                
                # Validate the token has required permissions
                $missingScopes = @()
                foreach ($scope in $Scopes) {
                    if (-not (Test-GraphPermissions -RequiredPermissions @($scope) -ResourceName "Azure PowerShell token")) {
                        $missingScopes += $scope
                    }
                }
                
                if ($missingScopes.Count -gt 0) {
                    Write-Warning "Azure PowerShell token is missing required API permissions:"
                    $missingScopes | ForEach-Object { Write-Warning "  - $_" }
                    Write-Host "`nThis is NOT a role assignment issue - even Global Admins need these API permissions consented." -ForegroundColor Yellow
                    Write-Host "`nTo get a token with proper permissions, run:" -ForegroundColor Yellow
                    Write-Host "  Connect-ScEntraGraph -UseDeviceCode" -ForegroundColor Cyan
                    Write-Host "`nThis will open a browser for authentication and request the required permissions." -ForegroundColor White
                    Write-Host "You can continue, but PIM and role assignment data will be incomplete.`n" -ForegroundColor Yellow
                }
                else {
                    Write-Host "✓ Authenticated using Azure PowerShell context with all required permissions" -ForegroundColor Green
                }
                
                return $true
            }
        }
    }
    catch {
        Write-Verbose "Azure PowerShell not available: $_"
    }

    try {
        $cliToken = az account get-access-token --resource https://graph.microsoft.com 2>$null | ConvertFrom-Json
        if ($cliToken -and $cliToken.accessToken) {
            $script:GraphAccessToken = $cliToken.accessToken
            
            # Validate the token has required permissions
            $missingScopes = @()
            foreach ($scope in $Scopes) {
                if (-not (Test-GraphPermissions -RequiredPermissions @($scope) -ResourceName "Azure CLI token")) {
                    $missingScopes += $scope
                }
            }
            
            if ($missingScopes.Count -gt 0) {
                Write-Warning "Azure CLI token is missing required API permissions:"
                $missingScopes | ForEach-Object { Write-Warning "  - $_" }
                Write-Host "`nThis is NOT a role assignment issue - even Global Admins need these API permissions consented." -ForegroundColor Yellow
                Write-Host "`nTo get a token with proper permissions, run:" -ForegroundColor Yellow
                Write-Host "  Connect-ScEntraGraph -UseDeviceCode" -ForegroundColor Cyan
                Write-Host "`nThis will open a browser for authentication and request the required permissions." -ForegroundColor White
                Write-Host "You can continue, but PIM and role assignment data will be incomplete.`n" -ForegroundColor Yellow
            }
            else {
                Write-Host "✓ Authenticated using Azure CLI with all required permissions" -ForegroundColor Green
            }
            
            return $true
        }
    }
    catch {
        Write-Verbose "Azure CLI not available: $_"
    }

    Write-Warning "No existing authentication found. Please provide an access token or authenticate using Azure PowerShell/CLI first."
    Write-Host "`nTo authenticate, use one of the following methods:" -ForegroundColor Yellow
    Write-Host "1. Azure PowerShell: Connect-AzAccount" -ForegroundColor Cyan
    Write-Host "2. Azure CLI: az login" -ForegroundColor Cyan
    Write-Host "3. Provide access token: Connect-ScEntraGraph -AccessToken <token>" -ForegroundColor Cyan

    return $false
}
