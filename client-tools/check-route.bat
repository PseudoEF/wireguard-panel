<# : --- часть для cmd: запускает этот же файл как PowerShell-скрипт ---
@echo off
chcp 65001 >nul
set "WGCHECK_ARGS=%*"
powershell -NoProfile -ExecutionPolicy Bypass -Command "iex ((Get-Content -LiteralPath '%~f0' -Encoding UTF8) -join [char]10)"
pause
exit /b
#>
# Проверка: идёт ли трафик к IP/домену через VPN (WireGuard) или напрямую + трассировка в стиле mtr.
# Использование: двойной клик (спросит адрес) или  check-route.bat site.ru 1.2.3.4
# Вердикт строится по двум признакам:
#   1) таблица маршрутов Windows — именно по ней WireGuard (AllowedIPs) решает, что пускать в туннель;
#   2) первый хоп трассировки — твой роутер (напрямую) или VPN-сервер.

[Console]::OutputEncoding = [Text.Encoding]::UTF8

function Get-Via([string]$ip) {
    try {
        $route = Find-NetRoute -RemoteIPAddress $ip -ErrorAction Stop |
            Where-Object { $_.DestinationPrefix } | Select-Object -First 1
    } catch { return $null }
    if (-not $route) { return $null }
    $ad = Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue
    [pscustomobject]@{
        Alias = $route.InterfaceAlias
        Vpn   = [bool]($ad -and $ad.InterfaceDescription -like "*WireGuard*")
        Route = $route.DestinationPrefix
    }
}

# Шлюз обычной сети (роутер), мимо туннеля
$wgIndexes = @(Get-NetAdapter -ErrorAction SilentlyContinue |
    Where-Object { $_.InterfaceDescription -like "*WireGuard*" } | ForEach-Object ifIndex)
$LanGateway = (Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
    Where-Object { $wgIndexes -notcontains $_.ifIndex -and $_.NextHop -ne "0.0.0.0" } |
    Sort-Object RouteMetric | Select-Object -First 1).NextHop

function Invoke-Mtr([string]$ip, [int]$maxHops = 20, [int]$probes = 4, [int]$timeout = 800) {
    $ping = New-Object Net.NetworkInformation.Ping
    $buf = New-Object byte[] 32
    $sw = New-Object Diagnostics.Stopwatch
    $hops = @()
    $dead = 0
    Write-Host ("  {0,3}  {1,-40} {2,7} {3,6} {4,6} {5,6}" -f "#", "Хоп", "Потери", "Сред", "Лучш", "Худш") -ForegroundColor DarkGray
    for ($ttl = 1; $ttl -le $maxHops; $ttl++) {
        $opt = New-Object Net.NetworkInformation.PingOptions($ttl, $true)
        $addr = $null; $rtts = @(); $reached = $false
        for ($i = 0; $i -lt $probes; $i++) {
            $sw.Restart()
            try { $r = $ping.Send($ip, $timeout, $buf, $opt) } catch { $r = $null }
            $sw.Stop()
            if ($r -and ($r.Status -eq "TtlExpired" -or $r.Status -eq "Success")) {
                if (-not $addr) { $addr = $r.Address.ToString() }
                $rtts += [int]$sw.ElapsedMilliseconds
                if ($r.Status -eq "Success") { $reached = $true }
            }
        }
        $loss = [int](100 * ($probes - $rtts.Count) / $probes)
        if ($rtts) {
            $st = $rtts | Measure-Object -Average -Minimum -Maximum
            $line = "  {0,3}  {1,-40} {2,6}% {3,6} {4,6} {5,6}" -f $ttl, $addr, $loss, [int]$st.Average, $st.Minimum, $st.Maximum
            $color = if ($loss -ge 50) { "Yellow" } else { "Gray" }
            Write-Host $line -ForegroundColor $color
            $dead = 0
        } else {
            Write-Host ("  {0,3}  {1,-40} {2,6}%" -f $ttl, "???", 100) -ForegroundColor DarkGray
            $dead++
        }
        $hops += [pscustomobject]@{ Ttl = $ttl; Addr = $addr }
        if ($reached) { break }
        if ($dead -ge 4) { Write-Host "  ... дальше хопы не отвечают, трассировка остановлена" -ForegroundColor DarkGray; break }
    }
    return $hops
}

function Test-Target([string]$target) {
    $target = $target.Trim() -replace '^[a-zA-Z]+://', '' -replace '/.*$', ''
    if ($target -notmatch ':.*:') { $target = $target -replace ':\d+$', '' }  # порт, но не IPv6
    if (-not $target) { return }
    $parsed = $null
    if ([Net.IPAddress]::TryParse($target, [ref]$parsed)) {
        $ips = @($target)
    } else {
        try {
            $ips = @(Resolve-DnsName $target -Type A_AAAA -DnsOnly -ErrorAction Stop |
                Where-Object { $_.IPAddress } | ForEach-Object { $_.IPAddress } | Select-Object -Unique)
        } catch {
            Write-Host "`n$target : не удалось получить IP ($($_.Exception.Message))" -ForegroundColor Red
            return
        }
    }
    Write-Host ""
    Write-Host "=== $target" -ForegroundColor Cyan
    Write-Host "Маршруты (по таблице Windows):"
    $main = $null
    foreach ($ip in $ips) {
        $v = Get-Via $ip
        if (-not $v) {
            Write-Host ("  {0,-40} нет маршрута (для IPv6 — обычно нет IPv6 в сети)" -f $ip) -ForegroundColor DarkGray
            continue
        }
        if (-not $main -and $ip -notmatch ':') { $main = [pscustomobject]@{ Ip = $ip; Via = $v } }
        if ($v.Vpn) { Write-Host ("  {0,-40} ЧЕРЕЗ VPN  ({1}, маршрут {2})" -f $ip, $v.Alias, $v.Route) -ForegroundColor Green }
        else        { Write-Host ("  {0,-40} НАПРЯМУЮ   ({1}, маршрут {2})" -f $ip, $v.Alias, $v.Route) -ForegroundColor Yellow }
    }
    if (-not $main) { return }

    Write-Host ""
    Write-Host "Трассировка до $($main.Ip) (как mtr, займёт до минуты):"
    $hops = Invoke-Mtr $main.Ip
    $first = ($hops | Where-Object Addr | Select-Object -First 1).Addr

    Write-Host ""
    $hopViaLan = $LanGateway -and $first -eq $LanGateway
    if ($main.Via.Vpn -and -not $hopViaLan) {
        Write-Host "ВЕРДИКТ: $target идёт ЧЕРЕЗ VPN-сервер." -ForegroundColor Green
        if ($first) { Write-Host "         Первый хоп $first — VPN-сервер, не твой роутер ($LanGateway)." }
    } elseif (-not $main.Via.Vpn -and ($hopViaLan -or -not $first)) {
        Write-Host "ВЕРДИКТ: $target идёт НАПРЯМУЮ, мимо VPN (исключение работает)." -ForegroundColor Yellow
        if ($first) { Write-Host "         Первый хоп $first — твой роутер." }
    } else {
        Write-Host "ВЕРДИКТ: противоречиво — маршрут: $(if ($main.Via.Vpn) {'VPN'} else {'напрямую'}), первый хоп: $first (роутер: $LanGateway)." -ForegroundColor Red
        Write-Host "         Возможно, конфиг только что поменяли — переподключи туннель и проверь снова."
    }
    if ($ips.Count -gt 1) {
        Write-Host "         У домена несколько IP — трассировка по первому, маршруты остальных выше."
    }
}

$tunnels = @(Get-NetAdapter -ErrorAction SilentlyContinue |
    Where-Object { $_.InterfaceDescription -like "*WireGuard*" -and $_.Status -eq "Up" })
if ($tunnels) {
    Write-Host ("Туннель WireGuard активен: " + (($tunnels | ForEach-Object Name) -join ", ")) -ForegroundColor Green
} else {
    Write-Host "Туннель WireGuard НЕ подключён — всё пойдёт напрямую. Включи туннель и запусти снова." -ForegroundColor Red
}
if ($LanGateway) { Write-Host "Твой роутер (шлюз обычной сети): $LanGateway" }

$targets = @($env:WGCHECK_ARGS -split '\s+' | Where-Object { $_ })
if ($targets) {
    $targets | ForEach-Object { Test-Target $_ }
} else {
    while ($true) {
        Write-Host ""
        $t = Read-Host "Введи IP или домен (Enter — выход)"
        if (-not $t) { break }
        $t -split '\s+' | Where-Object { $_ } | ForEach-Object { Test-Target $_ }
    }
}
