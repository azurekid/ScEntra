function New-ScEntraServicePrincipal {
    <#
    .SYNOPSIS
        Creates a new service principal with the required Microsoft Graph permissions for ScEntra analysis.

    .DESCRIPTION
        This function automates the creation of an Azure AD application registration and service principal
        with all the Microsoft Graph application permissions required to run ScEntra security analysis.

        The function will:
        1. Create a new App Registration
        2. Create a service principal for the app
        3. Assign required Microsoft Graph application permissions
        4. Create a client secret (optional, can use certificate instead)
        5. Display connection information for use with ScEntra

        Uses direct Microsoft Graph REST API calls without requiring Az PowerShell modules.

        IMPORTANT: Admin consent is required for the permissions. The function will provide instructions
        on how to grant admin consent via the Azure Portal.

    .PARAMETER DisplayName
        The display name for the application registration. Defaults to "ScEntra Security Analysis".

    .PARAMETER CertificatePath
        Path to a .pfx certificate file for certificate-based authentication. If not provided, a client secret will be created.

    .PARAMETER CertificatePassword
        SecureString password for the certificate file (if using certificate authentication).

    .PARAMETER SecretExpirationMonths
        Number of months until the client secret expires. Default is 12 months. Maximum is 24 months.

    .PARAMETER SkipAdminConsentInstructions
        Skip displaying admin consent instructions at the end.

    .PARAMETER AccessToken
        Access token for Microsoft Graph API. If not provided, will attempt to get one from current session.

    .EXAMPLE
        New-ScEntraServicePrincipal -DisplayName "ScEntra Production"

        Creates a new service principal with a 12-month client secret.

    .EXAMPLE
        New-ScEntraServicePrincipal -DisplayName "ScEntra Prod" -SecretExpirationMonths 6

        Creates a new service principal with a 6-month client secret.

    .EXAMPLE
        $certPwd = Read-Host -AsSecureString -Prompt "Certificate Password"
        New-ScEntraServicePrincipal -DisplayName "ScEntra Prod" -CertificatePath "C:\certs\scentra.pfx" -CertificatePassword $certPwd

        Creates a new service principal using certificate-based authentication.

    .NOTES
        Requires:
        - Application Administrator role or Global Administrator role
        - Ability to grant admin consent for Microsoft Graph application permissions
        - Active authentication session with Microsoft Graph

    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $false)]
        [string]$DisplayName = "ScEntra Security Analysis",

        [Parameter(Mandatory = $false)]
        [string]$CertificatePath,

        [Parameter(Mandatory = $false)]
        [SecureString]$CertificatePassword,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 24)]
        [int]$SecretExpirationMonths = 12,

        [Parameter(Mandatory = $false)]
        [switch]$SkipAdminConsentInstructions,

        [Parameter(Mandatory = $false)]
        [string]$AccessToken
    )

    # Helper function to make Graph API calls
    function Invoke-ScEntraGraphRequest {
        param(
            [string]$Uri,
            [string]$Method = "GET",
            [hashtable]$Headers,
            [object]$Body
        )

        try {
            $params = @{
                Uri     = $Uri
                Method  = $Method
                Headers = $Headers
            }

            if ($Body) {
                $params.Body = ($Body | ConvertTo-Json -Depth 10)
                $params.ContentType = "application/json"
            }

            $response = Microsoft.PowerShell.Utility\Invoke-RestMethod @params
            return $response
        }
        catch {
            $errorDetails = ""
            if ($_.Exception.Response) {
                try {
                    # PowerShell 7+ often exposes HttpResponseMessage with content on .Content
                    if ($_.Exception.Response -is [System.Net.Http.HttpResponseMessage]) {
                        $errorDetails = $_.Exception.Response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                    }
                    # Windows PowerShell may still expose a response stream
                    elseif ($_.Exception.Response.PSObject.Methods.Name -contains 'GetResponseStream') {
                        $stream = $_.Exception.Response.GetResponseStream()
                        $reader = New-Object System.IO.StreamReader($stream)
                        $errorDetails = $reader.ReadToEnd()
                        $reader.Close()
                    }
                }
                catch {
                    # Keep original exception message even if response parsing fails
                }
            }
            Write-Error "Graph API call failed: $($_.Exception.Message). Details: $errorDetails"
            throw
        }
    }

    # Helper function to get access token
    function Get-GraphAccessToken {
        param(
            [string]$ProvidedToken,
            [switch]$SkipCachedTokens
        )

        $script:ScEntraAuthTokenSource = $null

        function Test-GraphTokenLifetime {
            param([string]$Token)

            if ([string]::IsNullOrWhiteSpace($Token)) {
                return $false
            }

            try {
                $tokenParts = $Token.Split('.')
                if ($tokenParts.Count -lt 2) {
                    return $false
                }

                $payload = $tokenParts[1].Replace('-', '+').Replace('_', '/')
                switch ($payload.Length % 4) {
                    2 { $payload += '==' }
                    3 { $payload += '=' }
                }

                $payloadJson = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload))
                $payloadObj = $payloadJson | ConvertFrom-Json -ErrorAction Stop

                if (-not $payloadObj.exp) {
                    return $false
                }

                $expiryUtc = [DateTimeOffset]::FromUnixTimeSeconds([int64]$payloadObj.exp).UtcDateTime
                # Require at least 2 minutes remaining to avoid mid-run expiration.
                return ($expiryUtc -gt (Get-Date).ToUniversalTime().AddMinutes(2))
            }
            catch {
                return $false
            }
        }

        function Convert-ToPlainTextToken {
            param([object]$TokenValue)

            if ($null -eq $TokenValue) {
                return $null
            }

            if ($TokenValue -is [string]) {
                return $TokenValue
            }

            if ($TokenValue -is [SecureString]) {
                return ($TokenValue | ConvertFrom-SecureString -AsPlainText)
            }

            return $TokenValue.ToString()
        }

        if ($ProvidedToken) {
            $script:ScEntraAuthTokenSource = "Provided -AccessToken"
            return $ProvidedToken
        }

        # Reuse token from existing ScEntra session when available
        if (-not $SkipCachedTokens) {
            if (-not [string]::IsNullOrEmpty($script:GraphAccessToken)) {
                if (Test-GraphTokenLifetime -Token $script:GraphAccessToken) {
                    $script:ScEntraAuthTokenSource = "Existing ScEntra script token"
                    return $script:GraphAccessToken
                }
                else {
                    Write-Verbose "Cached ScEntra script token is expired/invalid. Trying fresh token sources."
                }
            }

            if (-not [string]::IsNullOrEmpty($global:ScEntraAccessToken)) {
                if (Test-GraphTokenLifetime -Token $global:ScEntraAccessToken) {
                    $script:ScEntraAuthTokenSource = "Existing ScEntra global token"
                    return $global:ScEntraAccessToken
                }
                else {
                    Write-Verbose "Cached ScEntra global token is expired/invalid. Trying fresh token sources."
                }
            }
        }

        # Try to get token from current session
        try {
            # Check if we have an active Graph session
            $context = Get-MgContext -ErrorAction SilentlyContinue
            if ($context) {
                # Get token from current session
                $token = [Microsoft.Graph.Authentication.GraphSession]::Instance.AuthenticationProvider.GetAccessToken()
                if ($token) {
                    $script:ScEntraAuthTokenSource = "Microsoft Graph PowerShell context"
                    return $token
                }
            }
        }
        catch {
            # Ignore errors and try next method
        }

        # Try Azure PowerShell token
        try {
            $azContext = Get-AzContext -ErrorAction SilentlyContinue
            if ($azContext) {
                $azToken = Get-AzAccessToken -ResourceTypeName MSGraph -ErrorAction SilentlyContinue
                if (-not $azToken) {
                    $azToken = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com" -ErrorAction SilentlyContinue
                }

                if ($azToken -and $azToken.Token) {
                    $plainToken = Convert-ToPlainTextToken -TokenValue $azToken.Token

                    if (-not [string]::IsNullOrWhiteSpace($plainToken)) {
                        $script:ScEntraAuthTokenSource = "Azure PowerShell context"
                        return $plainToken
                    }
                }

                if ($azToken -and $azToken.AccessToken) {
                    $plainToken = Convert-ToPlainTextToken -TokenValue $azToken.AccessToken

                    if (-not [string]::IsNullOrWhiteSpace($plainToken)) {
                        $script:ScEntraAuthTokenSource = "Azure PowerShell context"
                        return $plainToken
                    }
                }

                if ($azToken -and $azToken.Token) {
                    $script:ScEntraAuthTokenSource = "Azure PowerShell context"
                    return $azToken.Token
                }
            }
        }
        catch {
            # Ignore errors and try next method
        }

        # Try Azure CLI token
        try {
            $cliToken = az account get-access-token --resource "https://graph.microsoft.com" 2>$null | ConvertFrom-Json
            if ($cliToken -and $cliToken.accessToken) {
                $script:ScEntraAuthTokenSource = "Azure CLI context"
                return $cliToken.accessToken
            }
        }
        catch {
            # Ignore errors
        }

        throw "No access token available. Authenticate first with Connect-ScEntraGraph, Connect-AzAccount, or az login, or provide -AccessToken."
    }

    # Required Microsoft Graph Application Permissions for ScEntra
    # Validated against actual Graph API calls in the codebase
    $requiredPermissions = @(
        'User.Read.All'                              # Read all users (/users)
        'Group.Read.All'                             # Read all groups (/groups, /groups/{id}/owners)
        'GroupMember.Read.All'                       # Read group memberships (/groups/{id}/members, /groups/{id}/transitiveMembers)
        'Application.Read.All'                       # Read applications and service principals (/applications, /servicePrincipals, /servicePrincipals/{id}/appRoleAssignments)
        'DelegatedPermissionGrant.Read.All'          # Read OAuth2 permission grants (/servicePrincipals/{id}/oauth2PermissionGrants)
        'RoleManagement.Read.Directory'              # Read directory role assignments (/directoryRoles, /directoryRoles/{id}/members, /roleManagement/directory/roleDefinitions)
        'RoleEligibilitySchedule.Read.Directory'     # Read PIM eligible assignments (/roleManagement/directory/roleEligibilitySchedules, /roleManagement/directory/roleEligibilityScheduleInstances)
        'RoleAssignmentSchedule.Read.Directory'      # Read PIM active assignments (/roleManagement/directory/roleAssignmentSchedules)
        'PrivilegedAccess.Read.AzureADGroup'         # Read PIM for Groups (/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances, /identityGovernance/privilegedAccess/group/assignmentScheduleInstances)
    )

    # Check if using certificate or secret
    $useCertificate = -not [string]::IsNullOrEmpty($CertificatePath)

    if ($useCertificate) {
        if (-not (Test-Path -Path $CertificatePath)) {
            Write-Error "Certificate file not found: $CertificatePath"
            return
        }
        Write-Host "Using certificate-based authentication" -ForegroundColor Green
    }
    else {
        Write-Host "Using client secret authentication" -ForegroundColor Yellow
        Write-Host "   Secret will expire in $SecretExpirationMonths months" -ForegroundColor Gray
    }

    try {
        # Get access token
        Write-Host "Getting access token..." -ForegroundColor Cyan
        $token = Get-GraphAccessToken -ProvidedToken $AccessToken
        if (-not [string]::IsNullOrEmpty($script:ScEntraAuthTokenSource)) {
            Write-Host "   ✓ Token source: $script:ScEntraAuthTokenSource" -ForegroundColor Green
        }

        $headers = @{
            "Authorization" = "Bearer $token"
            "Content-Type"  = "application/json"
        }

        # Get tenant information
        Write-Host "Getting tenant information..." -ForegroundColor Cyan
        try {
            $tenantInfo = Invoke-ScEntraGraphRequest -Uri "https://graph.microsoft.com/beta/organization" -Headers $headers
        }
        catch {
            $authErrorText = $_.Exception.Message
            $isAuthFailure = $authErrorText -match "Authentication needed|Connect-MgGraph|InvalidAuthenticationToken|Access token has expired|Unauthorized|401"

            if ($isAuthFailure -and -not $AccessToken) {
                Write-Warning "Cached token failed authentication. Retrying with fresh token sources..."
                $token = Get-GraphAccessToken -SkipCachedTokens

                if (-not [string]::IsNullOrEmpty($script:ScEntraAuthTokenSource)) {
                    Write-Host "   ✓ Token source (retry): $script:ScEntraAuthTokenSource" -ForegroundColor Green
                }

                $headers["Authorization"] = "Bearer $token"
                $tenantInfo = Invoke-ScEntraGraphRequest -Uri "https://graph.microsoft.com/beta/organization" -Headers $headers
            }
            else {
                throw
            }
        }
        $tenantId = $tenantInfo.value[0].id
        Write-Host "   ✓ Tenant ID: $tenantId" -ForegroundColor Green

        # Get Microsoft Graph Service Principal to get permission IDs
        Write-Host "Getting Microsoft Graph permissions..." -ForegroundColor Cyan
        $graphSP = Invoke-ScEntraGraphRequest -Uri "https://graph.microsoft.com/beta/servicePrincipals?`$filter=appId eq '00000003-0000-0000-c000-000000000000'" -Headers $headers

        if (-not $graphSP.value -or $graphSP.value.Count -eq 0) {
            throw "Could not find Microsoft Graph service principal"
        }

        $graphSpObject = $graphSP.value[0]

        if ($PSCmdlet.ShouldProcess($DisplayName, "Create application registration")) {

            # Build required resource access
            Write-Host "Building permission requirements..." -ForegroundColor Cyan
            $resourceAccess = @()
            foreach ($permission in $requiredPermissions) {
                $appRole = $graphSpObject.appRoles | Where-Object { $_.value -eq $permission }
                if ($appRole) {
                    $resourceAccess += @{
                        id   = $appRole.id
                        type = "Role"
                    }
                    Write-Host "   + Added permission: $permission" -ForegroundColor Gray
                }
                else {
                    Write-Warning "   Permission not found in Graph SP: $permission"
                }
            }

            # Create the application
            Write-Host "Creating application registration..." -ForegroundColor Cyan
            $appBody = @{
                displayName            = $DisplayName
                requiredResourceAccess = @(
                    @{
                        resourceAppId  = "00000003-0000-0000-c000-000000000000"
                        resourceAccess = $resourceAccess
                    }
                )
            }

            try {
                $app = Invoke-ScEntraGraphRequest -Uri "https://graph.microsoft.com/beta/applications" -Method "POST" -Headers $headers -Body $appBody
            }
            catch {
                $createAppError = $_.Exception.Message
                if ($createAppError -match "403|Forbidden") {
                    throw "Forbidden creating application registration. The current token source '$script:ScEntraAuthTokenSource' does not have sufficient Microsoft Graph write permissions. Authenticate with Connect-MgGraph -Scopes 'Application.ReadWrite.All','Directory.Read.All' (or provide -AccessToken with equivalent permissions), then retry."
                }

                throw
            }
            Write-Host "   ✓ Created app: $($app.displayName)" -ForegroundColor Green
            Write-Host "   ✓ Application (client) ID: $($app.appId)" -ForegroundColor Green

            # Create Service Principal
            $spBody = @{
                appId = $app.appId
            }

            $sp = Invoke-ScEntraGraphRequest -Uri "https://graph.microsoft.com/beta/servicePrincipals" -Method "POST" -Headers $headers -Body $spBody
            Write-Host "   ✓ Created service principal: $($sp.id)" -ForegroundColor Green

            # Add credential
            Write-Host "[6/6] Creating credentials..." -ForegroundColor Cyan

            $credential = $null
            $clientSecret = $null

            if ($useCertificate) {
                # Load certificate
                $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertificatePath, $CertificatePassword)
                $certValue = [System.Convert]::ToBase64String($cert.GetRawCertData())

                $credentialBody = @{
                    type          = "AsymmetricX509Cert"
                    usage         = "Verify"
                    key           = $certValue
                    startDateTime = $cert.NotBefore.ToString("yyyy-MM-ddTHH:mm:ssZ")
                    endDateTime   = $cert.NotAfter.ToString("yyyy-MM-ddTHH:mm:ssZ")
                }

                $credential = Invoke-ScEntraGraphRequest -Uri "https://graph.microsoft.com/beta/applications/$($app.id)/addKey" -Method "POST" -Headers $headers -Body $credentialBody
                Write-Host "   ✓ Added certificate credential" -ForegroundColor Green
            }
            else {
                # Create client secret
                $endDate = (Get-Date).AddMonths($SecretExpirationMonths)
                $credentialBody = @{
                    passwordCredential = @{
                        displayName = "ScEntra Client Secret"
                        endDateTime = $endDate.ToString("yyyy-MM-ddTHH:mm:ssZ")
                    }
                }

                $credential = Invoke-ScEntraGraphRequest -Uri "https://graph.microsoft.com/beta/applications/$($app.id)/addPassword" -Method "POST" -Headers $headers -Body $credentialBody
                $clientSecret = $credential.secretText
                Write-Host "   ✓ Added client secret (expires: $($endDate.ToString('yyyy-MM-dd')))" -ForegroundColor Green
            }

            # Display admin consent information
            Write-Host "`nService principal created successfully!" -ForegroundColor Green

            if (-not $SkipAdminConsentInstructions) {
                Write-Host "`nADMIN CONSENT REQUIRED:" -ForegroundColor Yellow -BackgroundColor Black
                Write-Host "The service principal has been created, but admin consent is required for the permissions." -ForegroundColor Yellow
                Write-Host "Please visit the following URL to grant admin consent:" -ForegroundColor White

                $consentUrl = "https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/CallAnAPI/appId/$($app.appId)/isMSAApp~/false"
                Write-Host "   $consentUrl`n" -ForegroundColor Cyan

                Write-Host "After granting consent, you can use this service principal with ScEntra:" -ForegroundColor White
                Write-Host "   Connect-ScEntraGraph -TenantId '$tenantId' -ClientId '$($app.appId)' -ClientSecret '[SECRET]'" -ForegroundColor Gray
            }

            return [PSCustomObject]@{
                DisplayName     = $app.displayName
                ApplicationId   = $app.appId
                ObjectId        = $sp.id
                TenantId        = $tenantId
                ClientSecret    = $clientSecret
                CertThumbprint  = if ($useCertificate) { $cert.Thumbprint } else { $null }
                SecretExpiresOn = if (-not $useCertificate) { $endDate } else { $null }
                CertExpiresOn   = if ($useCertificate) { $cert.NotAfter } else { $null }
                Permissions     = $requiredPermissions
                ConsentUrl      = $consentUrl
            }
        }
    }
    catch {
        Write-Error "Failed to create service principal: $($_.Exception.Message)"
        if ($_.Exception.InnerException) {
            Write-Error "Inner exception: $($_.Exception.InnerException.Message)"
        }
        return
    }
}
