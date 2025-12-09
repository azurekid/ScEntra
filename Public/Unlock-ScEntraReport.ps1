function Unlock-ScEntraReport {
    <#
    .SYNOPSIS
        Decrypts an AES-256 protected ScEntra report file.

    .PARAMETER InputPath
        Path to the encrypted .enc file produced by Export-ScEntraReport.

    .PARAMETER OutputPath
        Path to write the decrypted file. Defaults to removing the .enc extension.

    .PARAMETER Password
        Password that was used when the report was encrypted.

    .PARAMETER Overwrite
        Overwrite the output path if it already exists.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$InputPath,
        [Parameter(Mandatory = $false)][string]$OutputPath,
        [Parameter(Mandatory = $false)][System.Security.SecureString]$Password,
        [Parameter(Mandatory = $false)][switch]$Overwrite
    )

    if (-not (Test-Path $InputPath)) {
        throw "Encrypted file not found: $InputPath"
    }

    if (-not $Password) {
        $Password = Read-Host "Enter password" -AsSecureString
    }

    if (-not $OutputPath) {
        if ($InputPath -like '*.enc') {
            $OutputPath = $InputPath -replace '\.enc$', ''
        }
        else {
            $OutputPath = "$InputPath.decrypted"
        }
    }

    if ((Test-Path $OutputPath) -and -not $Overwrite) {
        throw "Output path already exists. Use -Overwrite to replace it: $OutputPath"
    }

    $null = Unprotect-ScEntraFile -InputPath $InputPath -Password $Password -OutputPath $OutputPath
    Write-Information -InformationAction Continue "Decrypted file saved to: $OutputPath" -ForegroundColor Green

    return $OutputPath
}
