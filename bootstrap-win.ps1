param(
    [ValidateSet('run', 'setup', 'status')]
    [string] $Action = 'run'
)

# UBDEN uPenetrator - Windows-native (WSL YOK) tek-satirlik kurucu. WSL surumunun
# (bootstrap.ps1) ikizidir: ayni repo/tag, ayni sertlestirilmis indirme/kurulum
# deseni, ancak Kali WSL yerine Windows'ta calisan ubden-win.ps1'i baslatir.

$ErrorActionPreference = 'Stop'
$repo = 'ubden/ubden-cyber-wsl'
$tag = 'v5.0.0-wsl.38'
$installBase = Join-Path $env:LOCALAPPDATA 'Programs\UBDEN-Cyber'
$releaseRoot = Join-Path $installBase $tag
$entryPoint = Join-Path $releaseRoot 'ubden-win.ps1'
$requiredFiles = @(
    'ubden-win.ps1', 'windows-bridge.ps1', 'webapp.py', 'win_scan.py', 'win_proc.py',
    'win_tools.py', 'report_v2.py', 'device_inventory.py', 'wizard.py', 'eol_data.py',
    'service_probes.py', 'credential_probes.py', 'netbios_probe.py', 'web_identify.py', 'wifi_scan.py',
    'ai_operator.py', 'ai_analyst.py', 'power_manager.py', 'case_coverage.py', 'optional_tools.py',
    'attack_bridge.py', 'offensive-ext\pipeline.py', 'requirements.txt', 'sysvol_probe.py',
    'webui\serve.py', 'webui\index.html', 'webui\js\app.js'
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
    if ((Test-Path -LiteralPath $releaseRoot) -and -not (Test-Path -LiteralPath (Join-Path $releaseRoot 'ubden-wsl.ps1'))) {
        # Ayni tag'in WSL kurulumu zaten tam bir release birakmis olabilir; yalniz
        # gercekten eksik/bos ise hata ver.
        throw "Eksik kurulum dizini bulundu: $releaseRoot. Icerigini inceleyip yeniden deneyin."
    }
}

if (-not (Test-ReleaseFiles $releaseRoot)) {
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
            throw 'GitHub kaynak arsivinde gerekli UBDEN Windows dosyalari eksik'
        }
        if (Test-Path -LiteralPath $releaseRoot) {
            # WSL kurulumu ayni tag'i birakmissa ustune kopyalama; sadece eksikleri tamamla.
            foreach ($file in (Get-ChildItem -LiteralPath $roots[0].FullName -Recurse)) {
                $rel = $file.FullName.Substring($roots[0].FullName.Length).TrimStart('\', '/')
                $dest = Join-Path $releaseRoot $rel
                if ($file.PSIsContainer) { New-Item -ItemType Directory -Path $dest -Force | Out-Null }
                elseif (-not (Test-Path -LiteralPath $dest)) {
                    New-Item -ItemType Directory -Path (Split-Path -Parent $dest) -Force | Out-Null
                    Copy-Item -LiteralPath $file.FullName -Destination $dest
                }
            }
        }
        else {
            $destination = Assert-InstallChild $releaseRoot
            Move-Item -LiteralPath $roots[0].FullName -Destination $destination
        }
        Write-Host "Kaynak dosyalari: $releaseRoot"
    }
    finally {
        $staging = Assert-InstallChild $staging
        if (Test-Path -LiteralPath $staging) {
            Remove-Item -LiteralPath $staging -Recurse -Force
        }
    }
}

if (-not (Test-ReleaseFiles $releaseRoot)) { throw 'UBDEN Windows kaynak dosyalari dogrulanamadi' }

# 'irm | iex' ile calisildiginda gorev AYRI, kalici bir yonetici penceresinde
# calisir: etkilesimli oturum 'exit' ile ANI kapanmaz, UAC bir kez istenir,
# ilerleme/hatalar pencerede gorunur kalir ve bir log dosyasina yazilir.
$shell = if (Get-Command pwsh.exe -ErrorAction SilentlyContinue) { 'pwsh.exe' } else { 'powershell.exe' }
$log = Join-Path $installBase 'setup-win-log.txt'
$inner = @"
`$ErrorActionPreference = 'Stop'
try { Start-Transcript -Path '$log' -Append | Out-Null } catch {}
try {
    & '$entryPoint' -Action '$Action'
    Write-Host ''
    Write-Host 'UBDEN uPenetrator hazir.' -ForegroundColor Green
} catch {
    Write-Host ''
    Write-Host ('UBDEN kurulum hatasi: ' + `$_.Exception.Message) -ForegroundColor Red
    Write-Host 'Ayrinti icin log: $log' -ForegroundColor Yellow
} finally {
    try { Stop-Transcript | Out-Null } catch {}
    Write-Host ''
    Read-Host 'Pencereyi kapatmak icin Enter tuslayin' | Out-Null
}
"@
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($inner))
Write-Host 'UBDEN uPenetrator ayri bir yonetici penceresinde baslatiliyor (UAC izni istenebilir)...'
try {
    Start-Process -FilePath $shell -Verb RunAs -WindowStyle Normal `
        -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $encoded) | Out-Null
    Write-Host 'Pencere acildi. Tarayici arayuzu orada baslar; bu pencereyi kapatabilirsiniz.'
}
catch {
    Write-Host "Yonetici penceresi acilamadi (UAC reddedilmis olabilir): $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Elle calistirmak icin yonetici PowerShell'de: & '$entryPoint' -Action $Action"
}
