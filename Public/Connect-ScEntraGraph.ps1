function Connect-ScEntraGraph {
    <#
    .SYNOPSIS
        Connects to Microsoft Graph API and obtains an access token

    .DESCRIPTION
        Authenticates to Microsoft Graph using device code flow or existing access token

    .PARAMETER AccessToken
        Existing access token to use for authentication

    .PARAMETER UseDeviceCode
        Use OAuth2 device code flow for interactive authentication using the Microsoft Graph PowerShell client ID. Note: Some organizations may block device code flow for security reasons. Use Azure PowerShell (Connect-AzAccount) or Azure CLI (az login) instead when possible.

    .PARAMETER ClientId
        Custom client ID to use for device code flow authentication. If not specified, uses the Microsoft Graph PowerShell client ID.

    .PARAMETER Scopes
        Array of permission scopes required

    .PARAMETER TenantId
        The tenant ID to authenticate against

    .EXAMPLE
        Connect-ScEntraGraph -Scopes "User.Read.All", "Group.Read.All"
    #>
    [CmdletBinding(DefaultParameterSetName = 'AccessToken')]
    param(
        [Parameter(Mandatory = $false, ParameterSetName = 'AccessToken')]
        [string]$AccessToken,

        [Parameter(Mandatory = $false, ParameterSetName = 'DeviceCode')]
        [switch]$UseDeviceCode,

        [Parameter(Mandatory = $false, ParameterSetName = 'DeviceCode')]
        [Parameter(Mandatory = $true, ParameterSetName = 'ClientSecret')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Certificate')]
        [string]$ClientId,

        [Parameter(Mandatory = $true, ParameterSetName = 'ClientSecret')]
        [string]$ClientSecret,

        [Parameter(Mandatory = $true, ParameterSetName = 'Certificate')]
        [string]$CertificateThumbprint,

        [Parameter(Mandatory = $false, ParameterSetName = 'DeviceCode')]
        [string[]]$Scopes = @(
            "Directory.Read.All",
            "RoleManagement.Read.Directory",
            "RoleEligibilitySchedule.Read.Directory",
            "RoleAssignmentSchedule.Read.Directory",
            "DelegatedPermissionGrant.Read.All"
        ),

        [Parameter(Mandatory = $false, ParameterSetName = 'DeviceCode')]
        [Parameter(Mandatory = $true, ParameterSetName = 'ClientSecret')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Certificate')]
        [string]$TenantId = "common"
    )

    # Handle different authentication methods based on parameter sets
    switch ($PSCmdlet.ParameterSetName) {
        'ClientSecret' {
            Write-Host "Authenticating with client secret..." -ForegroundColor Cyan
            
            $tokenRequest = @{
                Uri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
                Method = 'POST'
                Body = @{
                    client_id = $ClientId
                    client_secret = $ClientSecret
                    scope = "https://graph.microsoft.com/.default"
                    grant_type = "client_credentials"
                }
            }
            
            try {
                $tokenResponse = Invoke-RestMethod @tokenRequest
                $global:ScEntraAccessToken = $tokenResponse.access_token
                $global:ScEntraTokenExpires = (Get-Date).AddSeconds($tokenResponse.expires_in - 300)  # 5 min buffer
                Write-Host "✅ Successfully authenticated with client secret" -ForegroundColor Green
                return $global:ScEntraAccessToken
            }
            catch {
                Write-Error "Failed to authenticate with client secret: $($_.Exception.Message)"
                throw
            }
        }
        
        'Certificate' {
            Write-Host "Authenticating with certificate..." -ForegroundColor Cyan
            
            # Get certificate from store
            $cert = Get-ChildItem -Path "Cert:\CurrentUser\My\$CertificateThumbprint" -ErrorAction SilentlyContinue
            if (-not $cert) {
                $cert = Get-ChildItem -Path "Cert:\LocalMachine\My\$CertificateThumbprint" -ErrorAction SilentlyContinue
            }
            
            if (-not $cert) {
                throw "Certificate with thumbprint '$CertificateThumbprint' not found in certificate store"
            }
            
            # Create JWT assertion for certificate authentication
            $header = @{
                alg = "RS256"
                typ = "JWT"
                x5t = [Convert]::ToBase64String($cert.GetCertHash())
            } | ConvertTo-Json -Compress
            
            $payload = @{
                aud = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
                exp = [Math]::Round((Get-Date).AddMinutes(5).Subtract((Get-Date "1970-01-01")).TotalSeconds)
                iss = $ClientId
                jti = [Guid]::NewGuid().ToString()
                nbf = [Math]::Round((Get-Date).Subtract((Get-Date "1970-01-01")).TotalSeconds)
                sub = $ClientId
            } | ConvertTo-Json -Compress
            
            $headerBase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($header)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
            $payloadBase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payload)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
            
            $dataToSign = "$headerBase64.$payloadBase64"
            $signature = $cert.PrivateKey.SignData([System.Text.Encoding]::UTF8.GetBytes($dataToSign), [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
            $signatureBase64 = [Convert]::ToBase64String($signature).TrimEnd('=').Replace('+', '-').Replace('/', '_')
            
            $jwt = "$dataToSign.$signatureBase64"
            
            $tokenRequest = @{
                Uri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
                Method = 'POST'
                Body = @{
                    client_id = $ClientId
                    client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                    client_assertion = $jwt
                    scope = "https://graph.microsoft.com/.default"
                    grant_type = "client_credentials"
                }
            }
            
            try {
                $tokenResponse = Invoke-RestMethod @tokenRequest
                $global:ScEntraAccessToken = $tokenResponse.access_token
                $global:ScEntraTokenExpires = (Get-Date).AddSeconds($tokenResponse.expires_in - 300)  # 5 min buffer
                Write-Host "✅ Successfully authenticated with certificate" -ForegroundColor Green
                return $global:ScEntraAccessToken
            }
            catch {
                Write-Error "Failed to authenticate with certificate: $($_.Exception.Message)"
                throw
            }
        }
        
        'DeviceCode' {
            Write-Host "Using device code authentication..." -ForegroundColor Cyan
        }
        
        'AccessToken' {
            if ($AccessToken) {
                $global:ScEntraAccessToken = $AccessToken
                $global:ScEntraTokenExpires = (Get-Date).AddHours(1)  # Assume 1 hour validity
                Write-Host "✅ Using provided access token" -ForegroundColor Green
                return $global:ScEntraAccessToken
            }
        }
    }
    
    # Use Device Code Flow if requested or if no other method specified
    if ($UseDeviceCode -or $PSCmdlet.ParameterSetName -eq 'DeviceCode') {
        Write-Host "`nInitiating OAuth2 Device Code Flow..." -ForegroundColor Cyan
        
        # Use custom client ID if provided, otherwise use Microsoft Graph PowerShell client ID
        $clientId = if ($ClientId) { $ClientId } else { "14d82eec-204b-4c2f-b7e8-296a70dab67e" }
        
        # Build scope string with proper resource prefix
        # Each scope needs to be in the format: https://graph.microsoft.com/.default OR individual scopes with resource prefix
        $scopeString = "https://graph.microsoft.com/.default offline_access"
        
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
                    
                    # Validate token has required scopes
                    $tokenInfo = Get-GraphTokenScopeInfo
                    if ($tokenInfo -and $tokenInfo.Scopes) {
                        Write-Verbose "Granted scopes: $($tokenInfo.Scopes -join ', ')"
                        $missingScopes = $Scopes | Where-Object { $_ -notin $tokenInfo.Scopes }
                        if ($missingScopes) {
                            Write-Warning "Some requested scopes were not granted: $($missingScopes -join ', ')"
                        }
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
        
        # Validate token has required scopes
        $tokenInfo = Get-GraphTokenScopeInfo
        if ($tokenInfo -and $tokenInfo.Scopes) {
            Write-Verbose "Token scopes: $($tokenInfo.Scopes -join ', ')"
            $missingScopes = $Scopes | Where-Object { $_ -notin $tokenInfo.Scopes }
            if ($missingScopes) {
                Write-Warning "Provided token is missing required scopes: $($missingScopes -join ', ')"
                Write-Host "Consider using device code flow for full permissions: Connect-ScEntraGraph -UseDeviceCode" -ForegroundColor Yellow
            }
        }
        return $true
    }

    try {
        $azContext = Get-AzContext -ErrorAction SilentlyContinue
        if ($azContext) {
            $token = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com" -ErrorAction SilentlyContinue
            if ($token) {
                $script:GraphAccessToken = $token.Token | ConvertFrom-SecureString -AsPlainText
                Write-Host "✓ Authenticated using Azure PowerShell context" -ForegroundColor Green
                
                # Validate token has required scopes
                $tokenInfo = Get-GraphTokenScopeInfo
                if ($tokenInfo -and $tokenInfo.Scopes) {
                    Write-Verbose "Token scopes: $($tokenInfo.Scopes -join ', ')"
                    $missingScopes = $Scopes | Where-Object { $_ -notin $tokenInfo.Scopes }
                    if ($missingScopes) {
                        Write-Warning "Azure PowerShell token is missing required scopes: $($missingScopes -join ', ')"
                        Write-Host "Consider using device code flow for full permissions: Connect-ScEntraGraph -UseDeviceCode" -ForegroundColor Yellow
                    }
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
            Write-Host "✓ Authenticated using Azure CLI context" -ForegroundColor Green
            
            # Validate token has required scopes
            $tokenInfo = Get-GraphTokenScopeInfo
            if ($tokenInfo -and $tokenInfo.Scopes) {
                Write-Verbose "Token scopes: $($tokenInfo.Scopes -join ', ')"
                $missingScopes = $Scopes | Where-Object { $_ -notin $tokenInfo.Scopes }
                if ($missingScopes) {
                    # Write-Warning "Azure CLI token is missing required scopes: $($missingScopes -join ', ')"
                    Write-Host "Consider using device code flow for full permissions: Connect-ScEntraGraph -UseDeviceCode" -ForegroundColor Yellow
                }
            }
            return $true
        }
    }
    catch {
        Write-Verbose "Azure CLI not available: $_"
    }

    Write-Warning "No existing authentication found. Please authenticate using one of the methods below."
    Write-Host "`nRecommended authentication methods:" -ForegroundColor Yellow
    Write-Host "1. Azure PowerShell: Connect-AzAccount" -ForegroundColor Cyan
    Write-Host "2. Azure CLI: az login" -ForegroundColor Cyan
    Write-Host "3. Provide access token: Connect-ScEntraGraph -AccessToken <token>" -ForegroundColor Cyan
    Write-Host "4. Device Code Flow (if not blocked): Connect-ScEntraGraph -UseDeviceCode" -ForegroundColor Cyan

    return $false
}
