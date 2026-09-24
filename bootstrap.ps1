param(
    [ValidateSet('run', 'setup', 'status')]
    [string] $Action = 'run'
)

$ErrorActionPreference = 'Stop'
$repo = 'ubden/ubden-cyber-wsl'
$tag = 'v4.8.1-wsl.3'
$installBase = Join-Path $env:LOCALAPPDATA 'Programs\UBDEN-Cyber'
$releaseRoot = Join-Path $installBase $tag
$entryPoint = Join-Path $releaseRoot 'ubden-wsl.ps1'
$requiredFiles = @(
    'ubden-wsl.ps1', 'windows-bridge.ps1', 'windows-browser.py',
    'wsl-bootstrap.sh', 'install.sh', 'wizard.py', 'requirements.txt'
)

function Assert-InstallChild([string] $Path) {
    $base = [IO.Path]::GetFullPath($installBase).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    $child = [IO.Path]::GetFullPath($Path)
    if (-not $child.StartsWith($base, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Kurulum yolu beklenen dizin disinda: $child"
    }
    return $child
}

function Test-ReleaseFiles([string] $Root) {
    foreach ($file in $requiredFiles) {
        if (-not (Test-Path -LiteralPath (Join-Path $Root $file) -PathType Leaf)) {
            return $false
        }
    }
    return $true
}

if (-not (Test-ReleaseFiles $releaseRoot)) {
    if (Test-Path -LiteralPath $releaseRoot) {
        throw "Eksik kurulum dizini bulundu: $releaseRoot. Icerigini inceleyip yeniden deneyin."
    }

    New-Item -ItemType Directory -Path $installBase -Force | Out-Null
    $staging = Assert-InstallChild (Join-Path $installBase ('.staging-' + [guid]::NewGuid().ToString('N')))
    New-Item -ItemType Directory -Path $staging | Out-Null
    try {
        $zipPath = Join-Path $staging 'source.zip'
        $unpack = Join-Path $staging 'unpacked'
        $url = "https://github.com/$repo/archive/refs/tags/$tag.zip"
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        Write-Host "UBDEN $tag kaynak paketi GitHub'dan indiriliyor..."
        Invoke-WebRequest -Uri $url -OutFile $zipPath -UseBasicParsing
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $archive = [IO.Compression.ZipFile]::OpenRead($zipPath)
        try {
            if ($archive.Entries.Count -gt 500) { throw 'Kaynak arsivinde beklenenden cok dosya var' }
            $totalBytes = [long]0
            foreach ($item in $archive.Entries) {
                $name = $item.FullName
                if ($name.StartsWith('/') -or $name.Contains('\') -or
                    $name.Contains(':') -or $name -match '(^|/)\.\.?(/|$)') {
                    throw "Gecersiz arsiv yolu: $name"
                }
                $mode = ($item.ExternalAttributes -shr 16) -band 0xF000
                if ($mode -eq 0xA000) { throw "Sembolik bag iceren arsiv reddedildi: $name" }
                $totalBytes += $item.Length
                if ($totalBytes -gt 100MB) { throw 'Kaynak arsivi boyut sinirini asti' }
            }
        }
        finally { $archive.Dispose() }

        Expand-Archive -LiteralPath $zipPath -DestinationPath $unpack
        $roots = @(Get-ChildItem -LiteralPath $unpack -Directory)
        if ($roots.Count -ne 1 -or
            -not $roots[0].Name.StartsWith('ubden-cyber-wsl-', [StringComparison]::Ordinal)) {
            throw 'GitHub kaynak arsivinin kok dizini beklenenden farkli'
        }
        if (-not (Test-ReleaseFiles $roots[0].FullName)) {
            throw 'GitHub kaynak arsivinde gerekli UBDEN dosyalari eksik'
        }
        $destination = Assert-InstallChild $releaseRoot
        Move-Item -LiteralPath $roots[0].FullName -Destination $destination
        Write-Host "Kaynak dosyalari: $destination"
    }
    finally {
        $staging = Assert-InstallChild $staging
        if (Test-Path -LiteralPath $staging) {
            Remove-Item -LiteralPath $staging -Recurse -Force
        }
    }
}

if (-not (Test-ReleaseFiles $releaseRoot)) { throw 'UBDEN kaynak dosyalari dogrulanamadi' }
& $entryPoint -Action $Action
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
