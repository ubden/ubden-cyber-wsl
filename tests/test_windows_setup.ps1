$ErrorActionPreference = 'Stop'
$scriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'ubden-wsl.ps1'
$tokens = $null
$parseErrors = $null
$tree = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw 'ubden-wsl.ps1 PowerShell sözdizimi geçersiz' }
foreach ($name in @('Read-State', 'Save-State', 'Register-SetupResume',
                    'Set-MirroredConfig', 'Ensure-MirroredNetwork',
                    'Copy-VerifiedTree', 'Assert-VerifiedManifest',
                    'Assert-ExportDestination', 'Invoke-Setup')) {
    $node = $tree.Find({ param($item)
        $item -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $item.Name -eq $name
    }, $true)
    if (-not $node) { throw "Eksik işlev: $name" }
    Invoke-Expression $node.Extent.Text
}

& {
    function New-Item { param($Path, [switch] $Force) }
    function New-ItemProperty {
        param($Path, $Name, $Value, $PropertyType, [switch] $Force)
        $script:registeredResume = $Value
    }
    $Action = 'run'
    Register-SetupResume
    if ($script:registeredResume -notmatch '-Action run$') {
        throw 'run islemi yeniden baslatmadan sonra gorev sihirbazini surdurmuyor'
    }
    $Action = 'setup'
    Register-SetupResume
    if ($script:registeredResume -notmatch '-Action setup$') {
        throw 'setup islemi yeniden baslatmadan sonra yalniz kurulumu surdurmuyor'
    }
}

$scratch = Join-Path ([IO.Path]::GetTempPath()) ('ubden-windows-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch | Out-Null
try {
    $StateRoot = Join-Path $scratch 'state'
    $StateFile = Join-Path $StateRoot 'setup-state.json'
    $OriginalConfig = Join-Path $StateRoot 'wslconfig.original'
    $WslConfig = Join-Path $scratch '.wslconfig'
    $original = "[wsl2]`r`nmemory=4GB`r`nnetworkingMode=nat`r`n[experimental]`r`nautoMemoryReclaim=gradual`r`n"
    [IO.File]::WriteAllText($WslConfig, $original)
    function wsl.exe { $script:shutdownCalls++; $global:LASTEXITCODE = 0 }
    $script:shutdownCalls = 0
    Set-MirroredConfig
    $updated = [IO.File]::ReadAllText($WslConfig)
    if ($updated -notmatch 'networkingMode=mirrored' -or
        $updated -notmatch 'dnsTunneling=true' -or
        $updated -notmatch 'memory=4GB' -or
        $updated -notmatch 'autoMemoryReclaim=gradual') {
        throw 'Mirrored ayar eklenirken mevcut ayarlar korunmadı'
    }
    if ([IO.File]::ReadAllText($OriginalConfig) -ne $original) {
        throw 'Önceki WSL yapılandırması yedeklenmedi'
    }
    Set-MirroredConfig
    if ($script:shutdownCalls -ne 1) { throw 'Tekrarlanan setup WSL ağını yeniden başlattı' }
    [IO.File]::WriteAllText($WslConfig, $original)
    Remove-Item -LiteralPath $StateFile -Force
    function Test-MirroredNetwork { throw 'simulated mirrored failure' }
    $rolledBack = $false
    try { Ensure-MirroredNetwork } catch { $rolledBack = $true }
    if (-not $rolledBack -or [IO.File]::ReadAllText($WslConfig) -ne $original -or
        (Read-State).config_managed) {
        throw 'Başarısız mirrored ağ denetimi önceki yapılandırmayı geri getirmedi'
    }

    $source = Join-Path $scratch 'source'
    $destination = Join-Path $scratch 'export'
    New-Item -ItemType Directory -Path $source | Out-Null
    [IO.File]::WriteAllText((Join-Path $source 'engagement.json'), '{"schema":8}')
    $manifest = New-Object 'System.Collections.Generic.List[object]'
    $count = Copy-VerifiedTree $source $destination $manifest
    if ($count -ne 1 -or $manifest.Count -ne 1 -or
        $manifest[0].sha256 -ne (Get-FileHash (Join-Path $source 'engagement.json') -Algorithm SHA256).Hash.ToLowerInvariant()) {
        throw 'Rapor aktarımı veya SHA-256 doğrulaması başarısız'
    }
    Assert-VerifiedManifest $manifest
    [IO.File]::WriteAllText((Join-Path $source 'engagement.json'), '{"schema":9}')
    $changed = $false
    try { Assert-VerifiedManifest $manifest } catch { $changed = $true }
    if (-not $changed) { throw 'Kaynak rapor değişikliği imha öncesinde engellenmedi' }
    $SourceRoot = Join-Path $scratch 'project'
    $safeExport = Join-Path $scratch 'outside'
    if ((Assert-ExportDestination $safeExport) -ne $safeExport) {
        throw 'Güvenli aktarım konumu reddedildi'
    }
    foreach ($bad in @($StateRoot, (Join-Path $StateRoot 'reports'),
                       $SourceRoot, (Join-Path $env:LOCALAPPDATA 'Packages\KaliLinux'),
                       '\\wsl.localhost\kali-linux\reports')) {
        $rejected = $false
        try { Assert-ExportDestination $bad | Out-Null } catch { $rejected = $true }
        if (-not $rejected) { throw "Silinecek/WSL konumu reddedilmedi: $bad" }
    }
    $blockedDestination = Join-Path $scratch 'blocked-export'
    [IO.File]::WriteAllText($blockedDestination, 'existing file')
    $failed = $false
    try { Copy-VerifiedTree $source $blockedDestination $manifest | Out-Null }
    catch { $failed = $true }
    if (-not $failed -or -not (Test-Path -LiteralPath (Join-Path $source 'engagement.json'))) {
        throw 'Başarısız aktarım kaynak kanıtı korumadı'
    }
    function Invoke-Elevated {}
    function Ensure-Kali {}
    function Ensure-MirroredNetwork { throw 'WSL mirrored 0x8007054f' }
    function Get-PSDrive {
        [CmdletBinding()]
        param([string] $Name, [string] $PSProvider)
        [pscustomobject]@{ Free = 40GB }
    }
    function Get-CimInstance {
        [CmdletBinding()]
        param([string] $ClassName, [string] $Filter)
        [pscustomobject]@{ InstallState = 2 }
    }
    function Enable-WindowsOptionalFeature {
        [CmdletBinding()]
        param([switch] $Online, [string] $FeatureName, [switch] $All,
              [switch] $NoRestart)
        $script:enabledFeature = $FeatureName
    }
    function Register-SetupResume { $script:resumeRegistered = $true }
    $script:enabledFeature = ''
    $script:resumeRegistered = $false
    $setupStopped = $false
    $setupError = ''
    try { Invoke-Setup } catch { $setupStopped = $true; $setupError = $_.Exception.Message }
    $pending = Read-State
    if (-not $setupStopped -or $script:enabledFeature -ne 'HypervisorPlatform' -or
        -not $script:resumeRegistered -or -not $pending.hypervisor_platform_added -or
        -not $pending.setup_pending_reboot) {
        throw "0x8007054f kurtarma kaydı yok: $setupError; feature=$script:enabledFeature; resume=$script:resumeRegistered; pending=$($pending.setup_pending_reboot)"
    }
    $pending | Add-Member -NotePropertyName setup_reboot_baseline `
        -NotePropertyValue '2020-01-01T00:00:00Z' -Force
    Save-State $pending
    function Get-CimInstance {
        [CmdletBinding()]
        param([string] $ClassName, [string] $Filter)
        if ($ClassName -eq 'Win32_OperatingSystem') {
            [pscustomobject]@{ LastBootUpTime = Get-Date }
        } else {
            [pscustomobject]@{ InstallState = 1 }
        }
    }
    $script:enabledFeature = ''
    $script:resumeRegistered = $false
    try { Invoke-Setup } catch {}
    $afterReboot = Read-State
    if ($script:enabledFeature -or $script:resumeRegistered -or
        $afterReboot.setup_pending_reboot -or -not $afterReboot.setup_error) {
        throw 'Başarısız yeniden başlatma sonrası kurulum durumu yanlış raporlandı'
    }
    'Windows setup/export tests OK'
}
finally {
    if ([IO.Path]::GetFullPath($scratch).StartsWith([IO.Path]::GetFullPath([IO.Path]::GetTempPath()),
            [StringComparison]::OrdinalIgnoreCase)) {
        Remove-Item -LiteralPath $scratch -Recurse -Force
    }
}
