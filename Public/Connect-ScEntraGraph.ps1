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
        
        # Get module version for User-Agent
        $moduleVersion = '1.0.0'
        try {
            $module = Get-Module -Name ScEntra -ErrorAction SilentlyContinue
            if ($module) {
                $moduleVersion = $module.Version.ToString()
            }
        } catch { }
        
        $userAgent = "ScEntra/$moduleVersion (PowerShell/$($PSVersionTable.PSVersion))"
        
        # Request device code
        $deviceCodeRequest = @{
            Uri        = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/devicecode"
            Method     = 'POST'
            UserAgent  = $userAgent
            Body       = @{
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
                Uri       = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
                Method    = 'POST'
                UserAgent = $userAgent
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
                    $tokenInfo = Get-GraphTokenScopeInfo
                    if ($tokenInfo -and $tokenInfo.Scopes) {
                        Write-Verbose "Granted scopes: $($tokenInfo.Scopes -join ', ')"
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
        Write-Host "✓ Access token loaded" -ForegroundColor Green
        return $true
    }

    try {
        $azContext = Get-AzContext -ErrorAction SilentlyContinue
        if ($azContext) {
            $token = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com" -ErrorAction SilentlyContinue
            if ($token) {
                $script:GraphAccessToken = $token.Token | ConvertFrom-SecureString -AsPlainText
                Write-Host "✓ Authenticated using Azure PowerShell context" -ForegroundColor Green
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
            Write-Host "✓ Authenticated using Azure CLI context" -ForegroundColor Green
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
