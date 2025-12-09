function Convert-ScEntraSecureStringToText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]$SecureString
    )

    if (-not $SecureString) {
        return [string]::Empty
    }

    $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($SecureString)
    try {
        return [System.Runtime.InteropServices.Marshal]::PtrToStringUni($ptr)
    }
    finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($ptr)
    }
}

function Protect-ScEntraFile {
    <#
        Encrypts a file using AES-256-CBC with PBKDF2-derived key.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$InputPath,
        [Parameter(Mandatory = $true)][System.Security.SecureString]$Password,
        [Parameter(Mandatory = $false)][string]$OutputPath,
        [Parameter(Mandatory = $false)][int]$IterationCount = 200000,
        [Parameter(Mandatory = $false)][switch]$RemovePlaintext
    )

    if (-not (Test-Path $InputPath)) {
        throw "Input file not found: $InputPath"
    }

    if (-not $OutputPath) {
        $OutputPath = "$InputPath.enc"
    }

    $contentBytes = [System.IO.File]::ReadAllBytes($InputPath)
    $saltBytes = New-Object byte[] 32
    $ivBytes = New-Object byte[] 16
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($saltBytes)
    $rng.GetBytes($ivBytes)

    $passwordText = Convert-ScEntraSecureStringToText -SecureString $Password

    try {
        $deriveBytes = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
            $passwordText,
            $saltBytes,
            $IterationCount,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256
        )
        $keyBytes = $deriveBytes.GetBytes(32)

        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.KeySize = 256
        $aes.BlockSize = 128
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key = $keyBytes
        $aes.IV = $ivBytes

        $memoryStream = New-Object System.IO.MemoryStream
        $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($memoryStream, $aes.CreateEncryptor(), [System.Security.Cryptography.CryptoStreamMode]::Write)
        $cryptoStream.Write($contentBytes, 0, $contentBytes.Length)
        $cryptoStream.FlushFinalBlock()
        $cipherBytes = $memoryStream.ToArray()
        $cryptoStream.Dispose()
        $memoryStream.Dispose()
        $aes.Dispose()
    }
    finally {
        $passwordText = $null
    }

    $envelope = [ordered]@{
        Magic      = 'ScEntraEncryptedReport'
        Version    = 1
        Algorithm  = 'AES-256-CBC'
        Iterations = $IterationCount
        Salt       = [System.Convert]::ToBase64String($saltBytes)
        IV         = [System.Convert]::ToBase64String($ivBytes)
        Payload    = [System.Convert]::ToBase64String($cipherBytes)
    }

    $json = $envelope | ConvertTo-Json -Depth 5
    [System.IO.File]::WriteAllText($OutputPath, $json)

    if ($RemovePlaintext) {
        Remove-Item -Path $InputPath -Force
    }

    return $OutputPath
}

function ConvertTo-ScEntraSelfDecryptingHtml {
    <#
        Embeds an encrypted HTML payload inside a self-decrypting wrapper that
        prompts for the password inside the browser using Web Crypto APIs.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$HtmlContent,
        [Parameter(Mandatory = $true)][System.Security.SecureString]$Password,
        [Parameter(Mandatory = $false)][int]$IterationCount = 1000,
        [Parameter(Mandatory = $false)][string]$DocumentTitle = 'ScEntra Encrypted Report'
    )

    if ($null -eq $HtmlContent) {
        $HtmlContent = ''
    }

    $saltBytes = New-Object byte[] 32
    $ivBytes = New-Object byte[] 16
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($saltBytes)
    $rng.GetBytes($ivBytes)

    $passwordText = Convert-ScEntraSecureStringToText -SecureString $Password
    $embeddedSecret = $null

    try {
        $plainBytes = [System.Text.Encoding]::UTF8.GetBytes($HtmlContent)
        $deriveBytes = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
            $passwordText,
            $saltBytes,
            $IterationCount,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256
        )
        $keyBytes = $deriveBytes.GetBytes(32)

        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.KeySize = 256
        $aes.BlockSize = 128
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key = $keyBytes
        $aes.IV = $ivBytes

        $memoryStream = New-Object System.IO.MemoryStream
        $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($memoryStream, $aes.CreateEncryptor(), [System.Security.Cryptography.CryptoStreamMode]::Write)
        $cryptoStream.Write($plainBytes, 0, $plainBytes.Length)
        $cryptoStream.FlushFinalBlock()
        $cipherBytes = $memoryStream.ToArray()
        $cryptoStream.Dispose()
        $memoryStream.Dispose()
        $aes.Dispose()
    }
    finally {
        $passwordText = $null
    }

    $envelope = [ordered]@{
        magic      = 'ScEntraEncryptedReport'
        version    = 2
        algorithm  = 'AES-256-CBC'
        iterations = $IterationCount
        salt       = [System.Convert]::ToBase64String($saltBytes)
        iv         = [System.Convert]::ToBase64String($ivBytes)
        payload    = [System.Convert]::ToBase64String($cipherBytes)
    }

    $envelopeJson = $envelope | ConvertTo-Json -Depth 5 -Compress

    $safeTitle = if ([string]::IsNullOrWhiteSpace($DocumentTitle)) {
        'ScEntra Encrypted Report'
    }
    else {
        [System.Net.WebUtility]::HtmlEncode($DocumentTitle)
    }

    $domIds = [ordered]@{
        shell    = 'encrypted-shell'
        message  = 'status-message'
        form     = 'password-form'
        password = 'password-input'
        button   = 'unlock-button'
        error    = 'error-message'
    }

    $idJson = $domIds | ConvertTo-Json -Compress

    $textMap = @{
        warn   = "This browser does not support the required Web Crypto APIs. Please open the report in a modern browser."
        prompt = "Enter the password to decrypt this ScEntra report."
        busy   = "Decrypting…"
        error  = "Incorrect password or corrupted file. Please try again."
    }

    $encodedTexts = @{}
    foreach ($key in $textMap.Keys) {
        $encodedTexts[$key] = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($textMap[$key]))
    }
    $encodedTextsJson = $encodedTexts | ConvertTo-Json -Compress

    $wrapper = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>$safeTitle</title>
    <style>
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        html, body {
            height: 100%;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Helvetica', 'Arial', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            color: #fff;
        }

        #$($domIds.shell) {
            width: min(460px, 94vw);
            padding: 3rem 2.5rem;
            background: rgba(255, 255, 255, 0.12);
            border-radius: 20px;
            box-shadow: 0 25px 60px rgba(0, 0, 0, 0.3);
            backdrop-filter: blur(16px);
            border: 1px solid rgba(255, 255, 255, 0.18);
        }

        h1 {
            font-size: 1.75rem;
            margin-bottom: 0.5rem;
            font-weight: 700;
            text-align: center;
        }

        #$($domIds.message) {
            text-align: center;
            margin: 1.25rem 0;
            font-size: 0.95rem;
            opacity: 0.92;
            min-height: 1.4rem;
        }

        label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 500;
            font-size: 0.9rem;
            opacity: 0.95;
        }

        input[type="password"] {
            width: 100%;
            padding: 1rem;
            border-radius: 12px;
            border: 2px solid rgba(255, 255, 255, 0.25);
            background: rgba(255, 255, 255, 0.15);
            color: #fff;
            font-size: 1rem;
            transition: all 0.2s;
        }

        input[type="password"]:focus {
            outline: none;
            border-color: rgba(255, 255, 255, 0.5);
            background: rgba(255, 255, 255, 0.22);
        }

        input[type="password"]::placeholder {
            color: rgba(255, 255, 255, 0.5);
        }

        button {
            margin-top: 1.5rem;
            width: 100%;
            padding: 1.1rem;
            border-radius: 12px;
            border: none;
            font-weight: 600;
            font-size: 1rem;
            letter-spacing: 0.5px;
            cursor: pointer;
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            color: #fff;
            transition: transform 0.2s, box-shadow 0.2s;
            box-shadow: 0 8px 20px rgba(0, 0, 0, 0.2);
        }

        button:hover:not(:disabled) {
            transform: translateY(-2px);
            box-shadow: 0 12px 25px rgba(0, 0, 0, 0.3);
        }

        button:disabled {
            opacity: 0.6;
            cursor: not-allowed;
        }

        #$($domIds.error) {
            margin-top: 1rem;
            text-align: center;
            font-size: 0.9rem;
            color: #ffebee;
            background: rgba(244, 67, 54, 0.3);
            padding: 0.8rem;
            border-radius: 8px;
            min-height: 1.4rem;
            display: none;
        }

        #$($domIds.error):not(:empty) {
            display: block;
        }
    </style>
</head>
<body>
    <main id="$($domIds.shell)">
        <h1>🔒 Encrypted Report</h1>
        <p id="$($domIds.message)"></p>
        <form id="$($domIds.form)">
            <label for="$($domIds.password)">Enter Password</label>
            <input id="$($domIds.password)" type="password" placeholder="Password" autocomplete="current-password" required>
            <button id="$($domIds.button)" type="submit">Unlock Report</button>
            <div id="$($domIds.error)" role="alert" aria-live="polite"></div>
        </form>
    </main>
    <script>
        const envelope = JSON.parse('$envelopeJson');
        (function() {
            const document = window.document;
            const ids = JSON.parse('$idJson');
            const encodedTexts = JSON.parse('$encodedTextsJson');

            const decodeText = (encoded) => {
                try {
                    return decodeURIComponent(window.atob(encoded).split('').map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)).join(''));
                } catch (e) {
                    return window.atob(encoded);
                }
            };

            const texts = {};
            Object.keys(encodedTexts).forEach(key => {
                texts[key] = decodeText(encodedTexts[key]);
            });

            const getElement = (key) => document.getElementById(ids[key]);
            const form = getElement('form');
            const passwordInput = getElement('password');
            const button = getElement('button');
            const message = getElement('message');
            const errorDiv = getElement('error');

            message.textContent = texts.prompt;

            const crypto = window.crypto?.subtle;
            if (!crypto) {
                message.textContent = texts.warn;
                form.style.display = 'none';
                return;
            }

            const encoder = new TextEncoder();
            const decoder = new TextDecoder();

            const base64ToBytes = (base64) => {
                const binaryString = window.atob(base64);
                const bytes = new Uint8Array(binaryString.length);
                for (let i = 0; i < binaryString.length; i++) {
                    bytes[i] = binaryString.charCodeAt(i);
                }
                return bytes;
            };

            const deriveKey = async (password, salt) => {
                return crypto.deriveKey(
                    {
                        name: 'PBKDF2',
                        salt: salt,
                        iterations: envelope.iterations,
                        hash: 'SHA-256'
                    },
                    await crypto.importKey('raw', encoder.encode(password), { name: 'PBKDF2' }, false, ['deriveKey']),
                    { name: 'AES-CBC', length: 256 },
                    false,
                    ['decrypt']
                );
            };

            const decryptData = async (password) => {
                const salt = base64ToBytes(envelope.salt);
                const iv = base64ToBytes(envelope.iv);
                const payload = base64ToBytes(envelope.payload);
                const key = await deriveKey(password, salt);
                return decoder.decode(await crypto.decrypt({ name: 'AES-CBC', iv: iv }, key, payload));
            };

            const displayReport = (html) => {
                document.open();
                document.write(html);
                document.close();
            };

            const unlockReport = async (password) => {
                const html = await decryptData(password);
                displayReport(html);
            };

            const setBusy = (busy) => {
                button.disabled = passwordInput.disabled = busy;
                button.textContent = busy ? texts.busy : 'Unlock Report';
            };

            const resetForm = () => {
                form.style.removeProperty('display');
                setBusy(false);
                message.textContent = texts.prompt;
                errorDiv.textContent = '';
                passwordInput.focus();
                passwordInput.select();
            };

            form.addEventListener('submit', async (event) => {
                event.preventDefault();
                errorDiv.textContent = '';
                setBusy(true);
                try {
                    await unlockReport(passwordInput.value);
                } catch (error) {
                    console.error('Failed to decrypt report', error);
                    errorDiv.textContent = texts.error;
                    setBusy(false);
                    passwordInput.focus();
                    passwordInput.select();
                }
            });

            passwordInput.focus();
        })();
    </script>
</body>
</html>
"@

    return $wrapper
}

function Unprotect-ScEntraFile {
    <#
        Decrypts a file produced by Protect-ScEntraFile
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$InputPath,
        [Parameter(Mandatory = $true)][System.Security.SecureString]$Password,
        [Parameter(Mandatory = $false)][string]$OutputPath
    )

    if (-not (Test-Path $InputPath)) {
        throw "Encrypted file not found: $InputPath"
    }

    $json = Get-Content -Path $InputPath -Raw
    $envelope = $json | ConvertFrom-Json -ErrorAction Stop

    if ($envelope.Magic -ne 'ScEntraEncryptedReport') {
        throw "File is not a ScEntra encrypted report."
    }

    $saltBytes = [System.Convert]::FromBase64String($envelope.Salt)
    $ivBytes = [System.Convert]::FromBase64String($envelope.IV)
    $cipherBytes = [System.Convert]::FromBase64String($envelope.Payload)
    $iterations = [int]$envelope.Iterations

    $passwordText = Convert-ScEntraSecureStringToText -SecureString $Password

    try {
        $deriveBytes = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
            $passwordText,
            $saltBytes,
            $iterations,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256
        )
        $keyBytes = $deriveBytes.GetBytes(32)

        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.KeySize = 256
        $aes.BlockSize = 128
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key = $keyBytes
        $aes.IV = $ivBytes

        $memoryStream = New-Object System.IO.MemoryStream
        $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($memoryStream, $aes.CreateDecryptor(), [System.Security.Cryptography.CryptoStreamMode]::Write)
        $cryptoStream.Write($cipherBytes, 0, $cipherBytes.Length)
        $cryptoStream.FlushFinalBlock()
        $plainBytes = $memoryStream.ToArray()
        $cryptoStream.Dispose()
        $memoryStream.Dispose()
        $aes.Dispose()
    }
    finally {
        $passwordText = $null
    }

    if ($OutputPath) {
        [System.IO.File]::WriteAllBytes($OutputPath, $plainBytes)
        return $OutputPath
    }

    return $plainBytes
}
