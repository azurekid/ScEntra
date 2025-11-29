function Export-ScEntraReport {
    <#
    .SYNOPSIS
        Exports analysis results to HTML report with visualizations

    .DESCRIPTION
        Generates an interactive HTML report with charts and tables showing the inventory
        and escalation path analysis

    .PARAMETER Users
        Array of users

    .PARAMETER Groups
        Array of groups

    .PARAMETER ServicePrincipals
        Array of service principals

    .PARAMETER AppRegistrations
        Array of app registrations

    .PARAMETER RoleAssignments
        Array of role assignments

    .PARAMETER PIMAssignments
        Array of PIM assignments

    .PARAMETER EscalationRisks
        Array of escalation risks

    .PARAMETER GraphData
        Graph nodes and edges describing escalation relationships

    .PARAMETER OutputPath
        Path where to save the HTML report. Used for both plaintext and encrypted output unless
        EncryptedOutputPath is supplied.

    .PARAMETER EncryptReport
        When supplied, wraps the report in a self-decrypting HTML shell that prompts for the
        password in the browser using AES-256 (PBKDF2 + AES-CBC) client-side decryption.

    .PARAMETER EncryptionPassword
        Optional secure-string password to use when EncryptReport is requested. If omitted you
        will be prompted interactively.

    .PARAMETER AutoUnlock
        When used with EncryptReport, embeds the password inside the HTML envelope so the browser
        decrypts the report automatically without prompting. Data at rest remains encrypted.

    .PARAMETER EncryptedOutputPath
        Optional path for the encrypted HTML wrapper. Defaults to OutputPath when omitted.

    .PARAMETER DeletePlaintextAfterEncryption
        Legacy switch retained for backward compatibility. No plaintext HTML is written when
        EncryptReport is enabled, so the switch has no effect.

    .EXAMPLE
        Export-ScEntraReport -Users $users -Groups $groups -OutputPath "C:\Reports\entra-report.html"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][array]$Users,
        [Parameter(Mandatory = $true)][array]$Groups,
        [Parameter(Mandatory = $true)][array]$ServicePrincipals,
        [Parameter(Mandatory = $true)][array]$AppRegistrations,
        [Parameter(Mandatory = $true)][array]$RoleAssignments,
        [Parameter(Mandatory = $false)][array]$PIMAssignments = @(),
        [Parameter(Mandatory = $false)][array]$EscalationRisks = @(),
        [Parameter(Mandatory = $false)][hashtable]$GraphData = $null,
        [Parameter(Mandatory = $false)][hashtable]$GroupMemberships = @{},
        [Parameter(Mandatory = $false)][hashtable]$OrganizationInfo = $null,
        [Parameter(Mandatory = $false)][string]$OutputPath,
        [Parameter(Mandatory = $false)][System.Security.SecureString]$EncryptionPassword,
        [Parameter(Mandatory = $false)][switch]$EncryptReport,
        [Parameter(Mandatory = $false)][switch]$AutoUnlock,
        [Parameter(Mandatory = $false)][string]$EncryptedOutputPath,
        [Parameter(Mandatory = $false)][switch]$DeletePlaintextAfterEncryption
    )

    if (-not $EncryptReport -and $EncryptionPassword) {
        $EncryptReport = $true
    }

    if (-not $EncryptReport -and $EncryptedOutputPath) {
        $EncryptReport = $true
    }

    if (-not $EncryptReport -and $DeletePlaintextAfterEncryption) {
        $EncryptReport = $true
    }

    if ($AutoUnlock -and -not $EncryptReport) {
        $EncryptReport = $true
    }

    Write-Verbose "Generating HTML report..."

    # Set default output path if not specified (use reports folder)
    if (-not $OutputPath) {
        $reportsFolder = Join-Path (Get-Location) "reports"
        if (-not (Test-Path $reportsFolder)) {
            New-Item -ItemType Directory -Path $reportsFolder -Force | Out-Null
        }
        $OutputPath = Join-Path $reportsFolder "ScEntra-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
    }

    $targetOutputPath = if ($EncryptReport -and $EncryptedOutputPath) { $EncryptedOutputPath } else { $OutputPath }
    $targetDirectory = Split-Path -Path $targetOutputPath -Parent
    if ($targetDirectory -and -not (Test-Path $targetDirectory)) {
        New-Item -ItemType Directory -Path $targetDirectory -Force | Out-Null
    }

    $stats = Get-ScEntraReportStatistics -Users $Users -Groups $Groups -ServicePrincipals $ServicePrincipals -AppRegistrations $AppRegistrations -RoleAssignments $RoleAssignments -PIMAssignments $PIMAssignments -EscalationRisks $EscalationRisks
    $roleDistribution = Get-ScEntraRoleDistribution -RoleAssignments $RoleAssignments
    $riskDistribution = Get-ScEntraRiskDistribution -EscalationRisks $EscalationRisks
    $generatedOn = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    $html = New-ScEntraReportDocument -Stats $stats -RoleDistribution $roleDistribution -RiskDistribution $riskDistribution -EscalationRisks $EscalationRisks -GraphData $GraphData -OrganizationInfo $OrganizationInfo -GeneratedOn $generatedOn

    try {
        if ($EncryptReport) {
            if (-not $EncryptionPassword) {
                $EncryptionPassword = Read-Host "Enter password to protect report" -AsSecureString
            }

            if ($DeletePlaintextAfterEncryption) {
                Write-Warning "DeletePlaintextAfterEncryption is no longer required. Encrypted HTML is written directly, so the switch is ignored."
            }

            $docTitle = if ($OrganizationInfo -and $OrganizationInfo.DisplayName) {
                "$($OrganizationInfo.DisplayName) | ScEntra Report"
            }
            else {
                'ScEntra Encrypted Report'
            }

            $encryptedHtml = ConvertTo-ScEntraSelfDecryptingHtml -HtmlContent $html -Password $EncryptionPassword -DocumentTitle $docTitle -AutoUnlock:$AutoUnlock
            [System.IO.File]::WriteAllText($targetOutputPath, $encryptedHtml, [System.Text.Encoding]::UTF8)
            Write-Host "Encrypted report saved to: $targetOutputPath" -ForegroundColor Cyan
        }
        else {
            $html | Out-File -FilePath $targetOutputPath -Encoding UTF8
            Write-Host "Report generated successfully: $targetOutputPath" -ForegroundColor Green
        }

        $jsonPath = [System.IO.Path]::ChangeExtension($targetOutputPath, '.json')
        $jsonData = @{
            GeneratedAt = Get-Date -Format 'o'
            OrganizationInfo = $OrganizationInfo
            Statistics = $stats
            Users = $Users | Select-Object id, displayName, userPrincipalName, accountEnabled, userType
            Groups = $Groups | Select-Object id, displayName, isAssignableToRole, isPIMEnabled, securityEnabled, memberCount
            ServicePrincipals = $ServicePrincipals | Select-Object id, displayName, appId, accountEnabled
            AppRegistrations = $AppRegistrations | Select-Object id, displayName, appId
            RoleAssignments = $RoleAssignments
            PIMAssignments = $PIMAssignments
            GroupMemberships = $GroupMemberships
            EscalationRisks = $EscalationRisks
            GraphData = $GraphData
        }

        $jsonData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
        Write-Host "JSON data exported to: $jsonPath" -ForegroundColor Green

        return $targetOutputPath
    }
    catch {
        Write-Error "Error generating report: $_"
        return $null
    }
}
