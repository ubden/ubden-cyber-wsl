param(
    [ValidateSet('run','setup','status','destroy')]
    [string] $Action = 'run',
    [string] $ExportTo = ''
)

$ErrorActionPreference = 'Stop'
$SourceRoot = Split-Path -Parent $PSCommandPath
$StateRoot = Join-Path $env:LOCALAPPDATA 'UBDEN'
$StateFile = Join-Path $StateRoot 'setup-state.json'
$WslConfig = Join-Path $env:USERPROFILE '.wslconfig'
$OriginalConfig = Join-Path $StateRoot 'wslconfig.original'

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-Elevated {
    if (Test-Administrator) { return }
    $shell = if (Get-Command pwsh.exe -ErrorAction SilentlyContinue) { 'pwsh.exe' } else { 'powershell.exe' }
    $quotedScript = $PSCommandPath.Replace("'", "''")
    $quotedExport = $ExportTo.Replace("'", "''")
    $command = "& '$quotedScript' -Action '$Action' -ExportTo '$quotedExport'"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    # The operator must see the interactive engagement and final destruction prompt.
    $process = Start-Process -FilePath $shell -Verb RunAs -WindowStyle Normal -Wait -PassThru `
        -ArgumentList @('-NoProfile','-EncodedCommand',$encoded)
    if ($process.ExitCode -ne 0) {
        $state = Read-State
        if ($state.setup_pending_reboot) {
            throw ('Windows yeniden baslatilinca setup surdurulecek: ' + $state.setup_pending_reboot)
        }
        if ($state.setup_error) { throw ('UBDEN kurulumu durdu: ' + $state.setup_error) }
        throw "Yukseltilmis islem $($process.ExitCode) koduyla durdu"
    }
    exit 0
}

function Get-Distros {
    if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) { return @() }
    $lines = @(& wsl.exe --list --quiet 2>$null)
    if ($LASTEXITCODE -ne 0) { return @() }
    return @($lines | ForEach-Object { ($_ -replace "`0", '').Trim() } | Where-Object { $_ })
}

function Read-State {
    if (Test-Path -LiteralPath $StateFile) {
        return Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json
    }
    return [pscustomobject]@{ config_existed = $false; config_managed = $false }
}

function Save-State($state) {
    New-Item -ItemType Directory -Path $StateRoot -Force | Out-Null
    $state | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $StateFile -Encoding UTF8
}

function Register-SetupResume {
    $key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    $resumeAction = if ($Action -eq 'run') { 'run' } else { 'setup' }
    $resume = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "' + $PSCommandPath + '" -Action ' + $resumeAction
    New-Item -Path $key -Force | Out-Null
    New-ItemProperty -Path $key -Name 'UBDEN-WSL-Setup' -Value $resume -PropertyType String -Force | Out-Null
}

function Set-MirroredConfig {
    $state = Read-State
    if (-not $state.config_managed) {
        New-Item -ItemType Directory -Path $StateRoot -Force | Out-Null
        $state.config_existed = Test-Path -LiteralPath $WslConfig
        if ($state.config_existed) { Copy-Item -LiteralPath $WslConfig -Destination $OriginalConfig -Force }
        $state.config_managed = $true
        Save-State $state
    }
    $lines = if (Test-Path -LiteralPath $WslConfig) {
        @(Get-Content -LiteralPath $WslConfig)
    } else { @() }
    $result = New-Object 'System.Collections.Generic.List[string]'
    $inWsl2 = $false
    $sawSection = $false
    $sawNetwork = $false
    $sawDns = $false
    foreach ($line in $lines) {
        if ($line -match '^\s*\[([^]]+)\]\s*$') {
            if ($inWsl2) {
                if (-not $sawNetwork) { $result.Add('networkingMode=mirrored') }
                if (-not $sawDns) { $result.Add('dnsTunneling=true') }
            }
            $inWsl2 = ($Matches[1] -ieq 'wsl2')
            if ($inWsl2) { $sawSection = $true }
        }
        if ($inWsl2 -and $line -match '^\s*networkingMode\s*=') {
            $result.Add('networkingMode=mirrored'); $sawNetwork = $true
        }
        elseif ($inWsl2 -and $line -match '^\s*dnsTunneling\s*=') {
            $result.Add('dnsTunneling=true'); $sawDns = $true
        }
        else { $result.Add($line) }
    }
    if ($inWsl2) {
        if (-not $sawNetwork) { $result.Add('networkingMode=mirrored') }
        if (-not $sawDns) { $result.Add('dnsTunneling=true') }
    }
    if (-not $sawSection) {
        $result.Add('')
        $result.Add('[wsl2]')
        $result.Add('networkingMode=mirrored')
        $result.Add('dnsTunneling=true')
    }
    $new = ($result -join "`r`n").TrimEnd() + "`r`n"
    $old = if (Test-Path -LiteralPath $WslConfig) { Get-Content -LiteralPath $WslConfig -Raw } else { '' }
    if ($new -ne $old) {
        [IO.File]::WriteAllText($WslConfig, $new, [Text.UTF8Encoding]::new($false))
        & wsl.exe --shutdown
        if ($LASTEXITCODE -ne 0) { throw 'WSL ag degisikligi sonrasi kapatilamadi' }
    }
}

function Convert-ToWslPath([string] $WindowsPath) {
    $result = @(& wsl.exe -d kali-linux -u root --exec wslpath -u $WindowsPath)
    if ($LASTEXITCODE -ne 0 -or -not $result) { throw "WSL yolu cevrilemedi: $WindowsPath" }
    return ($result[0] -replace "`0", '').Trim()
}

function Ensure-Kali {
    if (@(Get-Distros) -notcontains 'kali-linux') {
        Write-Host 'Kali WSL kuruluyor. Windows yeniden baslatma isteyebilir.'
        & wsl.exe --install -d kali-linux --no-launch
        if ($LASTEXITCODE -ne 0) { throw 'Kali WSL kurulumu basarisiz' }
        if (@(Get-Distros) -notcontains 'kali-linux') {
            Register-SetupResume
            throw 'WSL kurulumu yeniden baslatma bekliyor; setup oturum acildiginda surdurulecek'
        }
    }
    $rows = @(& wsl.exe --list --verbose 2>$null | ForEach-Object { ($_ -replace "`0", '').Trim() })
    $kali = @($rows | Where-Object { $_ -match 'kali-linux\s+.+\s+[12]\s*$' } | Select-Object -First 1)
    if ($kali -and $kali[0] -match 'kali-linux\s+.+\s+1\s*$') {
        Write-Host 'Mevcut Kali WSL 1; WSL 2 bicimine donusturuluyor.'
        & wsl.exe --set-version kali-linux 2
        if ($LASTEXITCODE -ne 0) { throw 'Kali WSL 2 donusumu basarisiz' }
    }
}

function Test-MirroredNetwork {
    $windows = @((Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.AddressState -eq 'Preferred' -and $_.IPAddress -notmatch '^(127|169\.254)\.' }).IPAddress)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'wsl.exe'
    $psi.Arguments = '-d kali-linux -u root --exec ip -j addr show'
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $process = [System.Diagnostics.Process]::Start($psi)
    $raw = $process.StandardOutput.ReadToEnd()
    $diagnostic = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    if ($diagnostic -match '0x8007054f') {
        throw 'WSL mirrored ag kurulumu 0x8007054f koduyla basarisiz oldu'
    }
    if ($process.ExitCode -ne 0) { throw "Kali ag arayuzleri okunamadi: $diagnostic" }
    $linux = @($raw | ConvertFrom-Json | ForEach-Object { $_.addr_info } |
        Where-Object { $_.family -eq 'inet' } | ForEach-Object { $_.local })
    if (-not @($windows | Where-Object { $linux -contains $_ }).Count) {
        $hint = if ($diagnostic) { ' WSL: ' + $diagnostic.Trim() } else { '' }
        throw ('Mirrored ag dogrulanamadi: Windows ve Kali IPv4 adresleri eslesmiyor.' + $hint)
    }
    Write-Host ('Mirrored ag dogrulandi; ortak IPv4: ' + (($windows | Where-Object { $linux -contains $_ }) -join ', '))
}

function Ensure-MirroredNetwork {
    $before = if (Test-Path -LiteralPath $WslConfig) {
        [IO.File]::ReadAllBytes($WslConfig)
    } else { $null }
    $stateBefore = Read-State
    try {
        Set-MirroredConfig
        Test-MirroredNetwork
    }
    catch {
        if ($null -eq $before) {
            if (Test-Path -LiteralPath $WslConfig) { Remove-Item -LiteralPath $WslConfig -Force }
        } else {
            [IO.File]::WriteAllBytes($WslConfig, $before)
        }
        if (-not $stateBefore.config_managed) {
            $rollbackState = Read-State
            $rollbackState.config_managed = $false
            Save-State $rollbackState
        }
        & wsl.exe --shutdown | Out-Null
        throw
    }
}

function Ensure-BrowserHelper {
    $venv = Join-Path $StateRoot 'windows-venv'
    $python = Join-Path $venv 'Scripts\python.exe'
    if (Test-Path -LiteralPath $python) { return }
    $found = Get-Command python.exe -ErrorAction SilentlyContinue
    $basePython = if ($found) { $found.Source } else { '' }
    if (-not $basePython) {
        if (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) {
            throw 'Windows Python ve winget bulunamadi; test tarayicisi kurulamaz'
        }
        & winget.exe install --exact --id Python.Python.3.13 --scope machine `
            --accept-source-agreements --accept-package-agreements | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Windows Python kurulumu basarisiz' }
        $basePython = @(
            (Join-Path $env:ProgramFiles 'Python313\python.exe'),
            (Join-Path $env:LOCALAPPDATA 'Programs\Python\Python313\python.exe')) |
            Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
        if (-not $basePython) { throw 'Kurulan Windows Python bulunamadi' }
    }
    & $basePython -m venv $venv
    if ($LASTEXITCODE -ne 0) { throw 'Windows browser Python ortami olusturulamadi' }
    & $python -m pip install --disable-pip-version-check 'playwright>=1.54,<2'
    if ($LASTEXITCODE -ne 0) { throw 'Windows Playwright kurulumu basarisiz' }
}

function Invoke-Setup {
    Invoke-Elevated
    $build = [Environment]::OSVersion.Version.Build
    if ($build -lt 22621) { throw 'Mirrored ag icin Windows 11 22H2 veya daha yenisi gerekli' }
    $stateDrive = [IO.Path]::GetPathRoot($env:LOCALAPPDATA).TrimEnd('\').TrimEnd(':')
    $drive = Get-PSDrive -Name $stateDrive -PSProvider FileSystem -ErrorAction Stop
    if ($drive.Free -lt 10GB) { throw 'WSL kurulumu icin Windows sistem diskinde en az 10 GiB bos alan gerekli' }
    $hostFreeKB = [math]::Floor($drive.Free / 1KB)
    New-Item -ItemType Directory -Path $StateRoot -Force | Out-Null
    Write-Host 'Mirrored ag ve DNS ayari Ubuntu dahil tum WSL 2 dagitimlarini etkiler.'
    Ensure-Kali
    $beforeNetwork = Read-State
    $bootTime = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).LastBootUpTime
    $rebootWasDone = [bool]($beforeNetwork.setup_pending_reboot -and
        $beforeNetwork.setup_reboot_baseline -and $bootTime -and
        $bootTime.ToUniversalTime() -gt [datetime]::Parse($beforeNetwork.setup_reboot_baseline))
    try { Ensure-MirroredNetwork }
    catch {
        if ($_.Exception.Message -match '0x8007054f|IPv4 adresleri eslesmiyor') {
            $feature = Get-CimInstance Win32_OptionalFeature -Filter "Name='HypervisorPlatform'" `
                -ErrorAction SilentlyContinue
            if ($feature -and $feature.InstallState -eq 2) {
                Enable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform -All `
                    -NoRestart -ErrorAction Stop | Out-Null
                $pending = Read-State
                $pending | Add-Member -NotePropertyName setup_pending_reboot `
                    -NotePropertyValue 'HypervisorPlatform enabled after WSL 0x8007054f' -Force
                $pending | Add-Member -NotePropertyName hypervisor_platform_added `
                    -NotePropertyValue $true -Force
                if ($bootTime) {
                    $pending | Add-Member -NotePropertyName setup_reboot_baseline `
                        -NotePropertyValue $bootTime.ToUniversalTime().ToString('o') -Force
                }
                Save-State $pending
                Register-SetupResume
                throw 'Mirrored WSL 0x8007054f: HypervisorPlatform acildi; Windows yeniden baslatilinca setup surdurulecek'
            }
            if ($rebootWasDone) {
                $failed = Read-State
                $failed | Add-Member -NotePropertyName setup_pending_reboot -NotePropertyValue '' -Force
                $failed | Add-Member -NotePropertyName setup_error `
                    -NotePropertyValue 'Mirrored WSL yeniden baslatmadan sonra da dogrulanamadi' -Force
                Save-State $failed
            }
        }
        throw
    }
    $state = Read-State
    if ($state.setup_pending_reboot) {
        $state | Add-Member -NotePropertyName setup_pending_reboot -NotePropertyValue '' -Force
        Save-State $state
    }
    $sourceFiles = @(Get-ChildItem -LiteralPath $SourceRoot -File |
        Where-Object { $_.Extension -in @('.py','.sh','.ps1','.json','.md','.txt') })
    $templateRoot = Join-Path $SourceRoot 'templates'
    if (Test-Path -LiteralPath $templateRoot) {
        $sourceFiles += @(Get-ChildItem -LiteralPath $templateRoot -File -Recurse)
    }
    $hashInput = $sourceFiles | Sort-Object FullName | ForEach-Object {
        (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }
    $sourceHash = $hashInput -join ':'
    $state = Read-State
    & wsl.exe -d kali-linux -u root --exec test -x /opt/ubden-cyber/start.sh
    $installed = ($LASTEXITCODE -eq 0)
    if (-not $installed -or $state.installed_hash -ne $sourceHash) {
        $sourceWsl = Convert-ToWslPath $SourceRoot
        $bootstrapWsl = Convert-ToWslPath (Join-Path $SourceRoot 'wsl-bootstrap.sh')
        # The fixed password goes to stdin only and is consumed only for a new account.
        'password' | & wsl.exe -d kali-linux -u root --exec env `
            "UBDEN_HOST_FREE_KB=$hostFreeKB" bash $bootstrapWsl $sourceWsl
        if ($LASTEXITCODE -ne 0) { throw 'Kali UBDEN kurulumu basarisiz' }
        $state = Read-State
        $state | Add-Member -NotePropertyName installed_hash -NotePropertyValue $sourceHash -Force
        Save-State $state
    }
    Ensure-BrowserHelper
    Write-Host 'UBDEN Kali WSL kurulumu tamamlandi.'
}

function Invoke-Status {
    $distros = @(Get-Distros)
    if (Get-Command wsl.exe -ErrorAction SilentlyContinue) { & wsl.exe --version }
    Write-Host ('WSL dagitimlari: ' + ($distros -join ', '))
    Write-Host ('Kali hazir: ' + [bool]($distros -contains 'kali-linux'))
    Write-Host ('WSL ag ayari: ' + $(if (Test-Path $WslConfig) {
        ((Get-Content $WslConfig | Select-String 'networkingMode\s*=') -join ', ')
    } else { 'varsayilan NAT' }))
    $state = Read-State
    if ($state.setup_pending_reboot) {
        Write-Host ('Kurulum yeniden baslatma bekliyor: ' + $state.setup_pending_reboot)
    }
    if ($state.setup_error) { Write-Host ('Kurulum hatasi: ' + $state.setup_error) }
    if ($state.hypervisor_platform_added) {
        Write-Host 'HypervisorPlatform: UBDEN kurulumu tarafindan acildi; destroy geri alacak'
    }
    $shell = if (Get-Command pwsh.exe -ErrorAction SilentlyContinue) { 'pwsh.exe' } else { 'powershell.exe' }
    $snapshot = (& $shell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `
        (Join-Path $SourceRoot 'windows-bridge.ps1') -Action inventory | ConvertFrom-Json)
    if ($snapshot.status -eq 'ok') {
        foreach ($nic in $snapshot.adapters) {
            $ips = @($nic.addresses | ForEach-Object { $_.address }) -join ', '
            Write-Host ("Windows [$($nic.index)] $($nic.name): $($nic.status); IP: $ips; VPN: $($nic.is_vpn)")
        }
        Write-Host ('Windows varsayilan rotalari: ' + (($snapshot.default_routes | ForEach-Object {
            "$($_.destination) via $($_.gateway) ifIndex=$($_.interface_index)" }) -join '; '))
    } else {
        Write-Host ("Windows envanteri alinamadi: $($snapshot.reason)")
    }
    if ($distros -contains 'kali-linux') {
        & wsl.exe -d kali-linux -u root --exec ip -j route show
        & wsl.exe -d kali-linux -u root --exec cat /etc/resolv.conf
        & wsl.exe -d kali-linux -u root --exec test -x /opt/ubden-cyber/start.sh
        Write-Host ('UBDEN kurulu: ' + [bool]($LASTEXITCODE -eq 0))
        $catalog = Convert-ToWslPath (Join-Path $SourceRoot 'tool_catalog.py')
        $tools = & wsl.exe -d kali-linux -u root --exec python3 $catalog | ConvertFrom-Json
        Write-Host ("Katalog: $($tools.catalog_count) listelenen arac; $(@($tools.tools | Where-Object installed).Count) kurulu (cektirdek araclar dahil)")
        foreach ($item in $tools.tools | Where-Object installed) {
            Write-Host ("  $($item.name): $($item.version) [$($item.mode)]")
        }
        Write-Host ('Windows test tarayicisi: ' + [bool](Test-Path -LiteralPath (Join-Path $StateRoot 'windows-venv\Scripts\python.exe')))
        Write-Host ('USB gecisi usbipd: ' + [bool](Get-Command usbipd.exe -ErrorAction SilentlyContinue))
        Write-Host ('Windows AD baglantisi: ' + [bool]$snapshot.part_of_domain)
    }
}

function Invoke-Run {
    Invoke-Setup
    $bridge = Join-Path $SourceRoot 'windows-bridge.ps1'
    & wsl.exe -d kali-linux -u root --exec env "UBDEN_WINDOWS_BRIDGE=$bridge" `
        /opt/ubden-cyber/start.sh
    if ($LASTEXITCODE -ne 0) { throw "UBDEN operasyonu $LASTEXITCODE koduyla durdu" }
}

function Copy-VerifiedTree([string] $Source, [string] $Destination,
                           [System.Collections.Generic.List[object]] $Manifest) {
    if (-not (Test-Path -LiteralPath $Source)) { return 0 }
    if ((Get-Item -LiteralPath $Source -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'Rapor kok dizini sembolik bag veya junction olamaz'
    }
    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    $links = @(Get-ChildItem -LiteralPath $Source -Recurse -Force -ErrorAction Stop |
        Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint })
    if ($links.Count) { throw 'Rapor agacinda sembolik bag veya junction var' }
    $files = @(Get-ChildItem -LiteralPath $Source -File -Recurse -Force)
    foreach ($file in $files) {
        if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Rapor agacinda sembolik bag var' }
        $relative = $file.FullName.Substring($Source.TrimEnd('\').Length).TrimStart('\')
        $target = Join-Path $Destination $relative
        New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force | Out-Null
        Copy-Item -LiteralPath $file.FullName -Destination $target -Force
        $sourceHash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
        $targetHash = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash
        if ($sourceHash -ne $targetHash) {
            throw "Rapor aktarimi dogrulanamadi: $relative"
        }
        $Manifest.Add(@{ source = $file.FullName; destination = $target;
                         sha256 = $sourceHash.ToLowerInvariant() })
    }
    return $files.Count
}

function Assert-VerifiedManifest([System.Collections.Generic.List[object]] $Manifest) {
    foreach ($entry in $Manifest) {
        if (-not (Test-Path -LiteralPath $entry.source) -or
            -not (Test-Path -LiteralPath $entry.destination)) {
            throw "Rapor devir dosyasi kayboldu: $($entry.source)"
        }
        $sourceHash = (Get-FileHash -LiteralPath $entry.source -Algorithm SHA256).Hash.ToLowerInvariant()
        $targetHash = (Get-FileHash -LiteralPath $entry.destination -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($sourceHash -ne $entry.sha256 -or $targetHash -ne $entry.sha256) {
            throw "Rapor devir ozeti degisti: $($entry.source)"
        }
    }
}

function Assert-ExportDestination([string] $Path) {
    if (-not $Path) { throw 'destroy icin -ExportTo WSL disi bir yol gerekli' }
    if ($Path -match '^\\\\(?:wsl\$|wsl\.localhost)(?:\\|$)') {
        throw 'Rapor hedefi WSL icinde olamaz'
    }
    $destination = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    if ($destination -match '(?i)\\AppData\\Local\\Packages(?:\\|$)') {
        throw 'Rapor hedefi WSL uygulama paket verisi icinde olamaz'
    }
    foreach ($blocked in @($SourceRoot, $StateRoot, (Join-Path $env:LOCALAPPDATA 'Packages'))) {
        $full = [IO.Path]::GetFullPath($blocked).TrimEnd('\')
        if ($destination.Equals($full, [StringComparison]::OrdinalIgnoreCase) -or
            $destination.StartsWith($full + '\', [StringComparison]::OrdinalIgnoreCase)) {
            throw "Rapor hedefi silinecek veya kaynak klasor icinde olamaz: $blocked"
        }
    }
    return $destination
}

function Invoke-Destroy {
    Invoke-Elevated
    $destinationRoot = Assert-ExportDestination $ExportTo
    $distros = @(Get-Distros | Sort-Object -Unique)
    if (-not $distros) { throw 'Kayitli WSL dagitimi bulunamadi' }
    $export = Join-Path $destinationRoot ('UBDEN-export-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
    New-Item -ItemType Directory -Path $export -Force | Out-Null
    $count = 0
    $manifest = New-Object 'System.Collections.Generic.List[object]'
    if ($distros -contains 'kali-linux') {
        $prefix = '\\wsl.localhost\kali-linux'
        if (-not (Test-Path -LiteralPath $prefix)) {
            throw 'Kali WSL dosya sistemi acilamadi; imha baslatilmadi'
        }
        if ((Test-Path -LiteralPath (Join-Path $prefix 'opt\ubden-cyber')) -and
            -not (Test-Path -LiteralPath (Join-Path $prefix 'opt\ubden-cyber\runs'))) {
            throw 'Kali UBDEN rapor klasoru eksik; imha baslatilmadi'
        }
        $count += Copy-VerifiedTree (Join-Path $prefix 'opt\ubden-cyber\runs') (Join-Path $export 'kali-opt-runs') $manifest
        $count += Copy-VerifiedTree (Join-Path $prefix 'home\ubden\Desktop\UBDEN-Cyber-Reports') (Join-Path $export 'kali-desktop-runs') $manifest
        $index = Join-Path $prefix 'opt\ubden-cyber\run-locations.json'
        if (Test-Path -LiteralPath $index) {
            $runs = @(Get-Content -LiteralPath $index -Raw | ConvertFrom-Json)
            $i = 0
            foreach ($run in $runs) {
                if ($run -isnot [string] -or -not $run.StartsWith('/') -or
                    @($run.Split('/') | Where-Object { $_ -eq '..' }).Count) {
                    throw 'Gorev dizini indeksinde gecersiz yol var'
                }
                if ($run -match '^/mnt/[a-z]/') { continue }
                if ($run.StartsWith('/opt/ubden-cyber/runs/') -or
                    $run.StartsWith('/home/ubden/Desktop/UBDEN-Cyber-Reports/')) { continue }
                $i++
                $candidate = Join-Path $prefix ($run.TrimStart('/') -replace '/', '\')
                if (-not (Test-Path -LiteralPath $candidate)) {
                    throw "Kayitli gorev dizini bulunamadi: $run"
                }
                $count += Copy-VerifiedTree $candidate (Join-Path $export ("indexed-run-$i")) $manifest
            }
        }
        # Locate older runs even when they predate run-locations.json. Stay on
        # the Kali filesystem so Windows-mounted data is never treated as WSL data.
        $discoverScript = @'
import json, os
root_device = os.stat('/').st_dev
matches = []
def fail(error):
    raise error
for base, directories, files in os.walk('/', topdown=True, followlinks=False, onerror=fail):
    keep = []
    for name in directories:
        path = os.path.join(base, name)
        if path in ('/proc', '/sys', '/dev', '/run', '/mnt') or os.path.islink(path):
            continue
        try:
            if os.stat(path, follow_symlinks=False).st_dev == root_device:
                keep.append(name)
        except OSError:
            continue
    directories[:] = keep
    if 'engagement.json' in files:
        matches.append(base)
        if len(matches) > 10000:
            raise RuntimeError('Too many engagement directories')
print(json.dumps(matches))
'@
        $discoveredJson = @(& wsl.exe -d kali-linux -u root --exec python3 -c $discoverScript)
        if ($LASTEXITCODE -ne 0) { throw 'Kali rapor kesfi tamamlanamadi; imha baslatilmadi' }
        $discovered = @(($discoveredJson -join "`n" | ConvertFrom-Json))
        $i = 0
        foreach ($run in $discovered) {
            if ($run -isnot [string] -or -not $run.StartsWith('/') -or
                @($run.Split('/') | Where-Object { $_ -eq '..' }).Count) {
                throw 'Kali rapor kesfinde gecersiz yol var'
            }
            if ($run.StartsWith('/opt/ubden-cyber/runs/') -or
                $run.StartsWith('/home/ubden/Desktop/UBDEN-Cyber-Reports/')) { continue }
            $i++
            $candidate = Join-Path $prefix ($run.TrimStart('/') -replace '/', '\')
            if (-not (Test-Path -LiteralPath $candidate)) {
                throw "Kesfedilen gorev dizini acilamadi: $run"
            }
            $count += Copy-VerifiedTree $candidate (Join-Path $export ("discovered-run-$i")) $manifest
        }
    }
    @{ schema = 1; files = @($manifest) } | ConvertTo-Json -Depth 6 |
        Set-Content -LiteralPath (Join-Path $export 'EXPORT_MANIFEST.json') -Encoding UTF8
    Write-Host "Dogrulanan rapor/kanit dosyasi: $count; aktarim: $export"
    Write-Host ('Kalici olarak silinecek dagitimlar: ' + ($distros -join ', '))
    $expected = 'SIL:' + ($distros -join ',')
    $typed = Read-Host "Son onay icin aynen $expected yazin"
    if ($typed -cne $expected) { throw 'Imha iptal edildi; rapor aktarimi korundu' }
    Assert-VerifiedManifest $manifest

    try { Set-PSReadLineOption -HistorySaveStyle SaveNothing -ErrorAction SilentlyContinue } catch {}
    $results = New-Object 'System.Collections.Generic.List[string]'
    $failures = New-Object 'System.Collections.Generic.List[string]'
    try {
      & wsl.exe --shutdown
      if ($LASTEXITCODE -ne 0) { throw 'WSL islemleri durdurulamadi' }
      foreach ($distro in $distros) {
          & wsl.exe --unregister $distro
          if ($LASTEXITCODE -ne 0) { throw "$distro kaldirilamadi" }
          $results.Add("unregistered:$distro")
      }
    $package = @(Get-AppxPackage -AllUsers *WindowsSubsystemForLinux* -ErrorAction SilentlyContinue |
        Sort-Object PackageFullName -Unique)
    foreach ($item in $package) {
        Remove-AppxPackage -Package $item.PackageFullName -AllUsers -ErrorAction Stop
        $results.Add('removed-wsl-app')
    }
    Disable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart -ErrorAction Stop | Out-Null
    $results.Add('disabled-wsl-feature')
    $state = Read-State
    if ($state.hypervisor_platform_added) {
        Disable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform -NoRestart -ErrorAction Stop | Out-Null
        $results.Add('restored-hypervisor-platform')
    }
    if ($state.config_managed) {
        if ($state.config_existed -and (Test-Path -LiteralPath $OriginalConfig)) {
            Copy-Item -LiteralPath $OriginalConfig -Destination $WslConfig -Force
        } elseif (Test-Path -LiteralPath $WslConfig) {
            Remove-Item -LiteralPath $WslConfig -Force
        }
        $results.Add('restored-wsl-config')
    }
    $expectedState = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'UBDEN'))
    if ((Test-Path -LiteralPath $StateRoot) -and
        [IO.Path]::GetFullPath($StateRoot) -eq $expectedState) {
        Remove-Item -LiteralPath $StateRoot -Recurse -Force
        $results.Add('removed-ubden-windows-state')
    }
    $historyPaths = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $profiles = @(Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPath -and (Test-Path -LiteralPath $_.LocalPath) })
    foreach ($profile in $profiles) {
        foreach ($relative in @('AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine',
                                'AppData\Roaming\Microsoft\PowerShell\PSReadLine')) {
            $historyDir = Join-Path $profile.LocalPath $relative
            if (Test-Path -LiteralPath $historyDir) {
                foreach ($item in Get-ChildItem -LiteralPath $historyDir -File -Force -Filter '*history*.txt') {
                    [void]$historyPaths.Add($item.FullName)
                }
            }
        }
    }
    try {
        $currentHistory = (Get-PSReadLineOption -ErrorAction Stop).HistorySavePath
        if ($currentHistory -and (Test-Path -LiteralPath $currentHistory)) {
            [void]$historyPaths.Add([IO.Path]::GetFullPath($currentHistory))
        }
    } catch {}
    foreach ($historyPath in $historyPaths) {
        Remove-Item -LiteralPath $historyPath -Force -ErrorAction Stop
    }
    Clear-History -ErrorAction SilentlyContinue
    $results.Add("cleared-powershell-history:$($historyPaths.Count)")
    $currentProcess = Get-CimInstance Win32_Process -Filter "ProcessId=$PID" -ErrorAction SilentlyContinue
    $remainingShells = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -in @('powershell.exe','pwsh.exe') -and
                       $_.ProcessId -ne $PID -and
                       $_.ProcessId -ne $currentProcess.ParentProcessId })
    if ($remainingShells.Count) {
        $failures.Add('Diger acik PowerShell oturumlari bellekte gecmis tutabilir; kapandiktan sonra gecmis dosyalarini yeniden kontrol edin')
    }
    } catch {
      $failures.Add($_.Exception.Message)
      throw
    } finally {
      $receipt = @{ at = (Get-Date).ToUniversalTime().ToString('o'); exported_files = $count;
                    exported_to = $export; completed = @($results); incomplete = @($failures);
                    source_preserved = $SourceRoot; reboot_required = $true }
      $receipt | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $export 'DESTRUCTION_RECEIPT.json') -Encoding UTF8
    }
    Write-Host "Imha islemleri sonlandi; eksikler tutanakta. Tutanak: $export\DESTRUCTION_RECEIPT.json. Windows yeniden baslatilmali."
}

try {
    switch ($Action) {
        'status' { Invoke-Status }
        'setup' { Invoke-Setup }
        'run' { Invoke-Run }
        'destroy' { Invoke-Destroy }
    }
}
catch {
    Write-Error $_
    exit 1
}
