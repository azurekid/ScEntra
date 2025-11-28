[CmdletBinding()]
param(
    [string]$SourceUri = 'https://learn.microsoft.com/en-us/graph/permissions-reference',
    [string]$OutputPath = (Join-Path -Path $PSScriptRoot -ChildPath 'graph-permissions.csv')
)

function Update-ScEntraPermissionMappings {
    [CmdletBinding()]
    param(
        [string]$SourceUri,
        [string]$OutputPath
    )

    function Convert-ToPlainText {
        param([string]$Value)
        if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
        $stripped = $Value -replace '<[^>]+>', ' '
        $decoded = [System.Net.WebUtility]::HtmlDecode($stripped)
        return ($decoded -replace '\s+', ' ').Trim()
    }

    function Get-ColumnPermissionType {
        param([string]$Header)
        if ([string]::IsNullOrWhiteSpace($Header)) { return 'Unknown' }
        switch -regex ($Header) {
            'Application' { return 'Role' }
            'Delegated' { return 'Scope' }
            'Resource' { return 'ResourceSpecific' }
            'Chat|Team|User|Tab' { return 'ResourceSpecific' }
            default { return 'Unknown' }
        }
    }

    Write-Verbose "Downloading permissions reference from $SourceUri"
    $response = Invoke-WebRequest -Uri $SourceUri -UseBasicParsing
    if (-not $response -or [string]::IsNullOrWhiteSpace($response.Content)) {
        throw 'Failed to download permissions reference page.'
    }

    $content = $response.Content
    $sectionRegex = [regex]::new('<h3 id="(?<id>[^"]+)">(?<name>[^<]+)</h3>\s*<table>(?<table>.*?)</table>', 'IgnoreCase, Singleline')
    $sections = $sectionRegex.Matches($content)
    if ($sections.Count -eq 0) {
        throw 'No permission tables were found in the downloaded content.'
    }

    $records = @()
    foreach ($section in $sections) {
        $permissionName = (Convert-ToPlainText $section.Groups['name'].Value)
        if (-not $permissionName) { continue }

        $tableHtml = $section.Groups['table'].Value
        $headerMatches = [regex]::Matches($tableHtml, '<th>(?<value>.*?)</th>', 'Singleline')
        if ($headerMatches.Count -lt 2) { continue }

        $headers = $headerMatches | ForEach-Object { Convert-ToPlainText $_.Groups['value'].Value }
        $dataHeaders = $headers[1..($headers.Count - 1)]

        if ($dataHeaders.Count -eq 0) { continue }

        $rowMatches = [regex]::Matches($tableHtml, '<tr>(?<cells>.*?)</tr>', 'Singleline')
        if ($rowMatches.Count -eq 0) { continue }

        $rowMap = @{}
        foreach ($rowMatch in $rowMatches) {
            $cellMatches = [regex]::Matches($rowMatch.Groups['cells'].Value, '<t[hd]>(?<value>.*?)</t[hd]>', 'Singleline')
            if ($cellMatches.Count -lt 2) { continue }

            $columnName = Convert-ToPlainText $cellMatches[0].Groups['value'].Value
            if (-not $columnName) { continue }

            $values = @()
            for ($i = 1; $i -lt $cellMatches.Count; $i++) {
                $values += ,(Convert-ToPlainText $cellMatches[$i].Groups['value'].Value)
            }
            $rowMap[$columnName] = $values
        }

        function Get-Value {
            param(
                [string]$RowName,
                [int]$Index
            )
            if (-not $rowMap.ContainsKey($RowName)) { return $null }
            $rowValues = $rowMap[$RowName]
            if ($Index -ge $rowValues.Count) { return $null }
            return $rowValues[$Index]
        }

        for ($colIndex = 0; $colIndex -lt $dataHeaders.Count; $colIndex++) {
            $identifier = Get-Value -RowName 'Identifier' -Index $colIndex
            if ([string]::IsNullOrWhiteSpace($identifier) -or $identifier -eq '-') { continue }

            $records += [PSCustomObject]@{
                Resource             = 'Microsoft Graph'
                Permission           = $permissionName
                PermissionId         = $identifier
                PermissionValue      = $permissionName
                Type                 = Get-ColumnPermissionType -Header $dataHeaders[$colIndex]
                Audience             = $dataHeaders[$colIndex]
                DisplayName          = Get-Value -RowName 'DisplayText' -Index $colIndex
                Description          = Get-Value -RowName 'Description' -Index $colIndex
                AdminConsentRequired = Get-Value -RowName 'AdminConsentRequired' -Index $colIndex
                SectionId            = $section.Groups['id'].Value
            }
        }
    }

    if ($records.Count -eq 0) {
        throw 'No permission rows with identifiers were found.'
    }

    $records = $records | Sort-Object Permission, Type, Audience
    $null = New-Item -Path (Split-Path -Path $OutputPath -Parent) -ItemType Directory -Force
    $records | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Verbose "Wrote $($records.Count) permission mappings to $OutputPath"
}

if ($MyInvocation.InvocationName -ne '.') {
    Update-ScEntraPermissionMappings -SourceUri $SourceUri -OutputPath $OutputPath
}