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
        - Application Administrator role
        - Ability to grant admin consent for Microsoft Graph application permissions
        
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
        [switch]$SkipAdminConsentInstructions
    )

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
        $context = Get-AzContext -ErrorAction SilentlyContinue
        if (-not $context) {
            Write-Host "   Not connected to Azure. Connecting..." -ForegroundColor Yellow
            Connect-AzAccount | Out-Null
            $context = Get-AzContext
        }

        # Get Microsoft Graph Service Principal
        $graphSP = Get-AzADServicePrincipal -ApplicationId "00000003-0000-0000-c000-000000000000" -ErrorAction Stop
        
        if ($PSCmdlet.ShouldProcess($DisplayName, "Create application registration")) {
            
            # Build required resource access
            $resourceAccess = @()
            foreach ($permission in $requiredPermissions) {
                $appRole = $graphSP.AppRole | Where-Object { $_.Value -eq $permission }
                if ($appRole) {
                    $resourceAccess += @{
                        Id   = $appRole.Id
                        Type = "Role"
                    }
                    Write-Host "   + Added permission: $permission" -ForegroundColor Gray
                }
                else {
                    Write-Warning "   Permission not found in Graph SP: $permission"
                }
            }

            # Create the application
            $app = New-AzADApplication -DisplayName $DisplayName -RequiredResourceAccess @{
                ResourceAppId  = "00000003-0000-0000-c000-000000000000"
                ResourceAccess = $resourceAccess
            } -ErrorAction Stop

            Write-Host "   ✓ Created app: $($app.DisplayName)" -ForegroundColor Green
            Write-Host "   ✓ Application (client) ID: $($app.AppId)" -ForegroundColor Green

            # Create Service Principal
            $sp = New-AzADServicePrincipal -ApplicationId $app.AppId -ErrorAction Stop

            # Add credential
            
            $credential = $null
            $clientSecret = $null
            
            if ($useCertificate) {
                # Load certificate
                $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertificatePath, $CertificatePassword)
                $certValue = [System.Convert]::ToBase64String($cert.GetRawCertData())
                
                $credential = New-AzADAppCredential -ApplicationId $app.AppId `
                    -CertValue $certValue `
                    -StartDate $cert.NotBefore `
                    -EndDate $cert.NotAfter `
                    -ErrorAction Stop
            }
            else {
                # Create client secret
                $endDate = (Get-Date).AddMonths($SecretExpirationMonths)
                $credential = New-AzADAppCredential -ApplicationId $app.AppId -EndDate $endDate -ErrorAction Stop
                $clientSecret = $credential.SecretText
            }

            # Display admin consent information
            Write-Host "`n[6/6] Admin consent required..." -ForegroundColor Cyan
            
            if (-not $SkipAdminConsentInstructions) {
                
                Write-Host "`nThe service principal has been created, but admin consent is required" -ForegroundColor Yellow
                
                $consentUrl = "https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/CallAnAPI/appId/$($app.AppId)/isMSAApp~/false"
                Write-Host "   $consentUrl`n" -ForegroundColor White
                
            }

            return [PSCustomObject]@{
                DisplayName     = $app.DisplayName
                ApplicationId   = $app.AppId
                ObjectId        = $sp.Id
                TenantId        = $context.Tenant.Id
                ClientSecret    = $clientSecret
                CertThumbprint  = if ($useCertificate) { $cert.Thumbprint } else { $null }
                SecretExpiresOn = if (-not $useCertificate) { $credential.EndDateTime } else { $null }
                CertExpiresOn   = if ($useCertificate) { $cert.NotAfter } else { $null }
                Permissions     = $requiredPermissions
                ConsentUrl      = "https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/CallAnAPI/appId/$($app.AppId)/isMSAApp~/false"
            }
        }
    }
    catch {
        Write-Error "Failed to create service principal: $_"
        return
    }
}
