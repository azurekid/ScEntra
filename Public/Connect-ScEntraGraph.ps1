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
        [string[]]$Scopes = @(
            "User.Read.All",
            "Group.Read.All",
            "Application.Read.All",
            "RoleManagement.Read.Directory",
            "RoleEligibilitySchedule.Read.Directory",
            "RoleAssignmentSchedule.Read.Directory",
            "PrivilgedgedAccess.Read.AzureADGroup"
        ),

        [Parameter(Mandatory = $false)]
        [string]$TenantId = "common"
    )

    if ($AccessToken) {
        $script:GraphAccessToken = $AccessToken
        Write-Verbose "Using provided access token"
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
            Write-Host "✓ Authenticated using Azure CLI" -ForegroundColor Green
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
