function Get-ScEntraRedactedName {
    <#
        Generates a deterministic redacted token for display names and labels
    #>
    param([string]$Value)

    if ([string]::IsNullOrEmpty($Value)) {
        return $Value
    }

    $hashSource = [System.Text.Encoding]::UTF8.GetBytes($Value)
    $hashBytes = [System.Security.Cryptography.SHA256]::Create().ComputeHash($hashSource)
    $hash = [System.BitConverter]::ToString($hashBytes).Replace('-', '').Substring(0, 8)
    return "REDACTED_$hash"
}

function Get-ScEntraRedactedEmail {
    <#
        Masks an email-like value while keeping format recognizable
    #>
    param([string]$Value)

    if ([string]::IsNullOrEmpty($Value)) {
        return $Value
    }

    if ($Value -notmatch '@') {
        return Get-ScEntraRedactedName -Value $Value
    }

    $parts = $Value -split '@'
    $local = $parts[0]
    $domain = $parts[1]
    $len = $local.Length

    switch ($len) {
        0 { $maskedLocal = $local }
        { $_ -le 1 } { $maskedLocal = $local }
        { $_ -le 4 } { $maskedLocal = $local[0] + '.' + $local[-1] }
        default { $maskedLocal = $local.Substring(0, 2) + '..' + $local.Substring($len - 2) }
    }

    if ($domain -like '*.onmicrosoft.com') {
        $maskedDomain = 'redacted.onmicrosoft.com'
    }
    else {
        $maskedDomain = 'redacted'
    }

    return "$maskedLocal@$maskedDomain"
}

function Invoke-ScEntraDataRedaction {
    <#
        Applies consistent redaction across all datasets used in the reports
    #>
    [CmdletBinding()]
    param(
        [Parameter()][array]$Users,
        [Parameter()][array]$Groups,
        [Parameter()][array]$ServicePrincipals,
        [Parameter()][array]$AppRegistrations,
        [Parameter()][array]$RoleAssignments,
        [Parameter()][array]$PIMAssignments,
        [Parameter()][array]$EscalationRisks,
        [Parameter()][hashtable]$GraphData,
        [Parameter()][psobject]$OrganizationInfo
    )

    $result = [ordered]@{}

    if ($Users) {
        $result.Users = $Users | ForEach-Object {
            $user = $_
            $user.DisplayName = Get-ScEntraRedactedName -Value $user.DisplayName
            if ($user.UserPrincipalName) { $user.UserPrincipalName = Get-ScEntraRedactedEmail -Value $user.UserPrincipalName }
            if ($user.Mail) { $user.Mail = Get-ScEntraRedactedEmail -Value $user.Mail }
            $user
        }
    }

    if ($Groups) {
        $result.Groups = $Groups | ForEach-Object {
            $group = $_
            $group.DisplayName = Get-ScEntraRedactedName -Value $group.DisplayName
            $group
        }
    }

    if ($ServicePrincipals) {
        $result.ServicePrincipals = $ServicePrincipals | ForEach-Object {
            $sp = $_
            $sp.DisplayName = Get-ScEntraRedactedName -Value $sp.DisplayName
            $sp
        }
    }

    if ($AppRegistrations) {
        $result.AppRegistrations = $AppRegistrations | ForEach-Object {
            $app = $_
            $app.DisplayName = Get-ScEntraRedactedName -Value $app.DisplayName
            $app
        }
    }

    if ($EscalationRisks) {
        $result.EscalationRisks = $EscalationRisks | ForEach-Object {
            $risk = $_
            if ($risk.UserName) { $risk.UserName = Get-ScEntraRedactedName -Value $risk.UserName }
            if ($risk.GroupName) { $risk.GroupName = Get-ScEntraRedactedName -Value $risk.GroupName }
            if ($risk.ServicePrincipalName) { $risk.ServicePrincipalName = Get-ScEntraRedactedName -Value $risk.ServicePrincipalName }
            if ($risk.AppName) { $risk.AppName = Get-ScEntraRedactedName -Value $risk.AppName }
            $risk
        }
    }

    if ($OrganizationInfo) {
        $result.OrganizationInfo = $OrganizationInfo
        if ($OrganizationInfo.DisplayName) {
            $result.OrganizationInfo.DisplayName = Get-ScEntraRedactedName -Value $OrganizationInfo.DisplayName
        }
        if ($OrganizationInfo.VerifiedDomains) {
            $result.OrganizationInfo.VerifiedDomains = $OrganizationInfo.VerifiedDomains | ForEach-Object { Get-ScEntraRedactedName -Value $_ }
        }
    }

    $roleNames = @()
    if ($RoleAssignments) {
        $roleNames += $RoleAssignments | ForEach-Object { $_.RoleName }
    }
    if ($PIMAssignments) {
        $roleNames += $PIMAssignments | ForEach-Object { $_.RoleName }
    }
    $roleNames = $roleNames | Where-Object { $_ } | Select-Object -Unique

    if ($GraphData -and $GraphData.nodes) {
        $redactedNodes = $GraphData.nodes | ForEach-Object {
            $node = $_
            if ($node.label -and $roleNames -notcontains $node.label) {
                $node.label = Get-ScEntraRedactedName -Value $node.label
            }
            if ($node.title -and $roleNames -notcontains $node.title) {
                $node.title = Get-ScEntraRedactedName -Value $node.title
            }
            if ($node.userPrincipalName) {
                $node.userPrincipalName = Get-ScEntraRedactedEmail -Value $node.userPrincipalName
            }
            if ($node.mail) {
                $node.mail = Get-ScEntraRedactedEmail -Value $node.mail
            }
            $node
        }

        $result.GraphData = @{
            nodes = $redactedNodes
            edges = $GraphData.edges
        }
    }

    return [pscustomobject]$result
}
