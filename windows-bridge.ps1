param(
    [ValidateSet('inventory','route','domain','browser','usb_list','usb_attach')]
    [string] $Action = 'inventory'
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)

function Emit-Json($Value) {
    $Value | ConvertTo-Json -Depth 10 -Compress | Write-Output
}

try {
    if ($Action -eq 'inventory') {
        $adapters = @(Get-NetAdapter -ErrorAction Stop | ForEach-Object {
            $nic = $_
            $addresses = @(Get-NetIPAddress -InterfaceIndex $nic.ifIndex -ErrorAction SilentlyContinue |
                Where-Object { $_.IPAddress -and $_.AddressState -eq 'Preferred' } |
                ForEach-Object { @{ address = $_.IPAddress; prefix = $_.PrefixLength; family = "$($_.AddressFamily)" } })
            $dns = @(Get-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -ErrorAction SilentlyContinue |
                ForEach-Object { $_.ServerAddresses } | Where-Object { $_ })
            @{
                name = $nic.Name
                index = $nic.ifIndex
                description = $nic.InterfaceDescription
                status = "$($nic.Status)"
                mac = $nic.MacAddress
                addresses = $addresses
                dns = $dns
                is_vpn = ($nic.InterfaceDescription -match 'VPN|TAP|Tunnel|Fortinet|Cato|WireGuard')
            }
        })
        $routes = @(Get-NetRoute -ErrorAction SilentlyContinue |
            Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' -or $_.DestinationPrefix -eq '::/0' } |
            ForEach-Object { @{ destination = $_.DestinationPrefix; gateway = $_.NextHop;
                                interface_index = $_.InterfaceIndex; metric = $_.RouteMetric } })
        $computer = Get-CimInstance Win32_ComputerSystem
        Emit-Json @{
            status = 'ok'
            schema = 1
            host = $env:COMPUTERNAME
            windows_build = [Environment]::OSVersion.Version.ToString()
            part_of_domain = [bool]$computer.PartOfDomain
            domain = "$($computer.Domain)"
            adapters = $adapters
            default_routes = $routes
        }
    }
    elseif ($Action -eq 'route') {
        $request = [Console]::In.ReadToEnd() | ConvertFrom-Json
        $ips = @($request.ips)
        if ($ips.Count -lt 1 -or $ips.Count -gt 256) { throw '1-256 sayisal IP bekleniyor' }
        $routes = foreach ($ip in $ips) {
            $parsed = $null
            if (-not [Net.IPAddress]::TryParse([string]$ip, [ref]$parsed)) {
                throw 'Rota sorgusu yalniz IP kabul eder'
            }
            try {
                $choice = Find-NetRoute -RemoteIPAddress "$parsed" -ErrorAction Stop |
                    Where-Object { $_.CimClass.CimClassName -eq 'MSFT_NetRoute' } |
                    Select-Object -First 1
                if ($null -eq $choice) { throw 'rota bulunamadi' }
                @{ ip = "$parsed"; status = 'ok'; interface_index = [int]$choice.InterfaceIndex;
                   destination = "$($choice.DestinationPrefix)"; gateway = "$($choice.NextHop)" }
            }
            catch {
                @{ ip = "$parsed"; status = 'error'; reason = $_.Exception.Message }
            }
        }
        Emit-Json @{ status = 'ok'; routes = @($routes) }
    }
    elseif ($Action -eq 'domain') {
        $computer = Get-CimInstance Win32_ComputerSystem
        if (-not $computer.PartOfDomain) {
            Emit-Json @{ status = 'skipped'; reason = 'Windows etki alanina bagli degil' }
            exit 0
        }
        Add-Type -AssemblyName System.DirectoryServices
        $root = New-Object System.DirectoryServices.DirectoryEntry('LDAP://RootDSE')
        $namingContext = [string]$root.Properties['defaultNamingContext'][0]
        if (-not $namingContext) { throw 'AD naming context bulunamadi' }
        $base = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$namingContext")
        $counts = @{}
        foreach ($entry in @(
            @{ label = 'users'; filter = '(&(objectCategory=person)(objectClass=user))' },
            @{ label = 'groups'; filter = '(objectClass=group)' },
            @{ label = 'computers'; filter = '(objectCategory=computer)' })) {
            $search = New-Object System.DirectoryServices.DirectorySearcher($base)
            $search.Filter = $entry.filter
            $search.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::None
            $search.SizeLimit = 1000
            $search.PageSize = 200
            $search.PropertiesToLoad.Add('distinguishedName') | Out-Null
            $found = $search.FindAll()
            try { $counts[$entry.label] = @{ observed_count = $found.Count; truncated_at = 1000 } }
            finally { $found.Dispose() }
        }
        $controller = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().FindDomainController().Name
        $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        $srvRecords = @()
        try {
            $srvRecords = @(Resolve-DnsName -Name ("_ldap._tcp.dc._msdcs." + $computer.Domain) `
                -Type SRV -ErrorAction Stop | Select-Object -First 16 |
                ForEach-Object { @{ name = $_.NameTarget; port = $_.Port; priority = $_.Priority } })
        } catch {}
        Emit-Json @{
            status = 'ok'; domain = "$($computer.Domain)"; naming_context = $namingContext
            domain_controller = $controller; source = 'Windows integrated read-only LDAP'
            forest = $forest.Name; forest_mode = "$($forest.ForestMode)"
            domain_mode = "$([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainMode)"
            dc_dns_records = $srvRecords; inventory = $counts
        }
    }
    elseif ($Action -eq 'usb_list') {
        if (-not (Get-Command usbipd.exe -ErrorAction SilentlyContinue)) {
            Emit-Json @{ status = 'missing_tool'; reason = 'usbipd-win kurulu degil' }
        } else {
            $devices = @(& usbipd.exe list 2>&1)
            Emit-Json @{ status = $(if ($LASTEXITCODE -eq 0) { 'ok' } else { 'error' });
                         lines = @($devices | ForEach-Object { "$_" }) }
        }
    }
    elseif ($Action -eq 'usb_attach') {
        $request = [Console]::In.ReadToEnd() | ConvertFrom-Json
        $busid = [string]$request.busid
        if ($busid -notmatch '^[0-9]{1,3}-[0-9]{1,3}$') { throw 'Gecersiz USB BusID' }
        if (-not (Get-Command usbipd.exe -ErrorAction SilentlyContinue)) {
            if (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) {
                throw 'usbipd-win ve winget bulunamadi'
            }
            & winget.exe install --interactive --exact dorssel.usbipd-win `
                --accept-source-agreements --accept-package-agreements | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'usbipd-win kurulumu basarisiz' }
            $env:Path += ';' + (Join-Path $env:ProgramFiles 'usbipd-win')
        }
        if (-not (Get-Command usbipd.exe -ErrorAction SilentlyContinue)) {
            Emit-Json @{ status = 'missing_tool'; reason = 'Kurulum sonrasi usbipd.exe bulunamadi' }
        } else {
            $bound = @(& usbipd.exe bind --busid $busid 2>&1)
            if ($LASTEXITCODE -ne 0 -and ($bound -join ' ') -notmatch 'already') {
                throw "USB bind basarisiz: $($bound -join ' ')"
            }
            $attached = @(& usbipd.exe attach --wsl --busid $busid 2>&1)
            if ($LASTEXITCODE -ne 0) { throw "USB attach basarisiz: $($attached -join ' ')" }
            Emit-Json @{ status = 'ok'; busid = $busid; detail = 'Yalniz secilen aygit WSL icine baglandi' }
        }
    }
    else {
        $request = [Console]::In.ReadToEnd()
        $managedPython = Join-Path $env:LOCALAPPDATA 'UBDEN\windows-venv\Scripts\python.exe'
        $python = if ($env:UBDEN_BROWSER_PYTHON) { $env:UBDEN_BROWSER_PYTHON }
                  elseif (Test-Path -LiteralPath $managedPython) { $managedPython }
                  else { 'python' }
        $browserScript = Join-Path $PSScriptRoot 'windows-browser.py'
        $response = $request | & $python $browserScript 2>&1
        if ($LASTEXITCODE -ne 0) { throw "Browser helper failed: $response" }
        $response | Write-Output
    }
}
catch {
    Emit-Json @{ status = 'error'; action = $Action; reason = $_.Exception.Message }
    exit 1
}
