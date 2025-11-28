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
        [Parameter(Mandatory = $false)][int]$IterationCount = 200000,
        [Parameter(Mandatory = $false)][string]$DocumentTitle = 'ScEntra Encrypted Report',
        [Parameter(Mandatory = $false)][switch]$AutoUnlock
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

        if ($AutoUnlock) {
            $embeddedSecret = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($passwordText))
        }
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

    if ($AutoUnlock -and $embeddedSecret) {
        $envelope.autoUnlock = $true
        $envelope.secret = $embeddedSecret
    }
    $envelopeJson = $envelope | ConvertTo-Json -Depth 5 -Compress

    $safeTitle = if ([string]::IsNullOrWhiteSpace($DocumentTitle)) {
        'ScEntra Encrypted Report'
    }
    else {
        [System.Net.WebUtility]::HtmlEncode($DocumentTitle)
    }

    $generateId = {
        param([string]$prefix)
        "$prefix$([System.Guid]::NewGuid().ToString('N').Substring(0, 6))"
    }

    $domIds = [ordered]@{
        shell    = & $generateId 'x'
        message  = & $generateId 'x'
        form     = & $generateId 'x'
        password = & $generateId 'x'
        button   = & $generateId 'x'
        error    = & $generateId 'x'
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
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>$safeTitle</title>
    <style>
        :root {
            color-scheme: dark light;
            font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            line-height: 1.5;
        }
        body {
            margin: 0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            background: radial-gradient(circle at top, #0f172a 0%, #020617 45%, #000 100%);
            color: #e2e8f0;
        }
        [data-role="shell"] {
            width: min(420px, 92vw);
            padding: 2.5rem;
            background: rgba(15, 23, 42, 0.85);
            border-radius: 18px;
            box-shadow: 0 20px 55px rgba(0, 0, 0, 0.45);
            border: 1px solid rgba(226, 232, 240, 0.08);
            backdrop-filter: blur(10px);
        }
        h1 {
            margin-top: 0;
            font-size: 1.45rem;
            letter-spacing: 0.04em;
        }
        [data-role="message"] {
            margin-top: 0.75rem;
            min-height: 1.4rem;
            font-size: 0.9rem;
            color: #cbd5f5;
        }
        [data-role="error"] {
            margin-top: 0.75rem;
            min-height: 1.4rem;
            font-size: 0.85rem;
            color: #fca5a5;
        }
        input[type="password"] {
            width: 100%;
            padding: 0.85rem 1rem;
            border-radius: 10px;
            border: 1px solid rgba(148, 163, 184, 0.6);
            background: rgba(15, 23, 42, 0.6);
            color: inherit;
            font-size: 1rem;
        }
        button {
            margin-top: 1.2rem;
            width: 100%;
            padding: 0.9rem 1rem;
            border-radius: 999px;
            border: none;
            font-weight: 600;
            letter-spacing: 0.03em;
            text-transform: uppercase;
            cursor: pointer;
            background: linear-gradient(120deg, #38bdf8, #6366f1, #a855f7);
            color: #fff;
        }
        button:disabled {
            opacity: 0.65;
            cursor: progress;
        }
    </style>
</head>
<body>
    <main id="$($domIds.shell)" data-role="shell">
        <h1>Unlock Report</h1>
        <p id="$($domIds.message)" data-role="message"></p>
        <form id="$($domIds.form)" data-role="form">
            <label for="$($domIds.password)">Password</label>
            <input id="$($domIds.password)" data-role="secret" type="password" name="password" autocomplete="current-password" required />
            <button id="$($domIds.button)" data-role="submit" type="submit">Unlock</button>
            <div id="$($domIds.error)" data-role="error" role="status" aria-live="polite"></div>
        </form>
    </main>
    <script>
        const e = $envelopeJson;
        (function () {
            const doc = document;
            const ids = $idJson;
            const phrases = $encodedTextsJson;

            const fromBase64 = (value) => {
                try {
                    return decodeURIComponent(window.atob(value).split('').map((ch) => '%' + ('00' + ch.charCodeAt(0).toString(16)).slice(-2)).join(''));
                }
                catch (err) {
                    return window.atob(value);
                }
            };

            const text = {};
            Object.keys(phrases).forEach((key) => {
                text[key] = fromBase64(phrases[key]);
            });

            const lookup = (key) => doc.getElementById(ids[key]);
            const form = lookup('form');
            const secret = lookup('password');
            const submit = lookup('button');
            const message = lookup('message');
            const error = lookup('error');

            message.textContent = text.prompt;

            const cryptoApi = (window.crypto || {}).subtle;
            if (!cryptoApi) {
                message.textContent = text.warn;
                form.style.display = 'none';
                return;
            }

            const encoder = new TextEncoder();
            const decoder = new TextDecoder();
            let autoUnlockSecret = (e.autoUnlock === true && typeof e.secret === 'string' && e.secret.length > 0) ? fromBase64(e.secret) : null;

            const b64ToBytes = (b64) => {
                const binary = window.atob(b64);
                const bytes = new Uint8Array(binary.length);
                for (let i = 0; i < binary.length; i += 1) {
                    bytes[i] = binary.charCodeAt(i);
                }
                return bytes;
            };

            const deriveKey = async (password, salt) => {
                const material = await cryptoApi.importKey('raw', encoder.encode(password), { name: 'PBKDF2' }, false, ['deriveKey']);
                return cryptoApi.deriveKey(
                    { name: 'PBKDF2', salt, iterations: e.iterations, hash: 'SHA-256' },
                    material,
                    { name: 'AES-CBC', length: 256 },
                    false,
                    ['decrypt']
                );
            };

            const decryptHtml = async (password) => {
                const salt = b64ToBytes(e.salt);
                const iv = b64ToBytes(e.iv);
                const payload = b64ToBytes(e.payload);
                const key = await deriveKey(password, salt);
                const buffer = await cryptoApi.decrypt({ name: 'AES-CBC', iv }, key, payload);
                return decoder.decode(buffer);
            };

            const renderReport = (html) => {
                document.open();
                document.write(html);
                document.close();
            };

            const unlockWithPassword = async (password) => {
                const decrypted = await decryptHtml(password);
                renderReport(decrypted);
            };

            const setBusy = (active) => {
                submit.disabled = active;
                secret.disabled = active;
                message.textContent = active ? text.busy : text.prompt;
            };

            const showPrompt = () => {
                form.style.removeProperty('display');
                setBusy(false);
                message.textContent = text.prompt;
                error.textContent = '';
                secret.focus();
                secret.select();
            };

            form.addEventListener('submit', async (event) => {
                event.preventDefault();
                error.textContent = '';
                setBusy(true);

                try {
                    await unlockWithPassword(secret.value);
                }
                catch (err) {
                    console.error('Failed to decrypt report', err);
                    error.textContent = text.error;
                    setBusy(false);
                    secret.focus();
                    secret.select();
                }
            });

            if (autoUnlockSecret) {
                form.style.display = 'none';
                setBusy(true);
                message.textContent = text.busy;

                unlockWithPassword(autoUnlockSecret).catch((err) => {
                    console.warn('Auto unlock failed', err);
                    autoUnlockSecret = null;
                    showPrompt();
                });
            }
            else {
                secret.focus();
            }
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
