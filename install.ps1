<#
  Установка WireGuard + веб-панели на Windows 10.
  Обычно запускается из wg-panel-setup.ps1 (он распаковывает проект и вызывает этот скрипт).
  Можно и напрямую, из PowerShell от имени администратора:

    powershell -ExecutionPolicy Bypass -File .\install.ps1 -Endpoint 1.2.3.4

  -Yes            не задавать вопросов (для полностью автоматической установки)
  -AdminPassword  пароль панели; если не указан при -Yes — будет сгенерирован и показан в конце
  -Resume         служебный: продолжение после перезагрузки (запускается задачей планировщика)

  NAT в Windows 10 (New-NetNat) работает только при установленных компонентах Hyper-V.
  Если их нет, скрипт включает их БЕЗ запуска гипервизора (hypervisorlaunchtype off —
  подходит и для VPS без вложенной виртуализации), ставит разовую задачу
  "wg-panel-resume" и после перезагрузки сам доделывает NAT. Итог — в файле на рабочем
  столе и в logs\resume.log.

  Скрипт только ДОБАВЛЯЕТ: туннель wg0, NAT для подсети VPN, два разрешающих
  правила фаервола (группа "wg-panel") и службу wg-panel. Существующие правила,
  RDP, IIS/сайты, сетевые адаптеры и маршруты не трогаются.
  Перед любыми изменениями выполняются проверки; при конфликте скрипт остановится.
  Повторный запуск безопасен (ключи и клиенты сохраняются).
#>
param(
    [string]$Endpoint = "",
    [int]$WgPort = 51820,
    [int]$PanelPort = 8443,
    [string]$Subnet = "10.8.0.0/24",
    [string]$AdminPassword = "",
    [switch]$Yes,
    [switch]$Resume
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"  # иначе Invoke-WebRequest в PS 5.1 качает очень медленно
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Root = $PSScriptRoot
$Data = Join-Path $Root "data"
$Logs = Join-Path $Root "logs"
$Iface = "wg0"
$TunnelService = 'WireGuardTunnel$wg0'
$PanelService = "wg-panel"
$FwGroup = "wg-panel"
$NatName = "wgpanel"
$WgDir = "C:\Program Files\WireGuard"
$ResumeTask = "wg-panel-resume"
$ResultNote = "C:\Users\Public\Desktop\wg-panel - итог установки.txt"
$AttemptsFile = Join-Path $Root "logs\resume-attempts.txt"
$attempt = 0

if ($Resume) {
    # Запуск задачей планировщика после перезагрузки: окна нет, всё пишем в лог.
    $Yes = $true
    New-Item -ItemType Directory -Force (Join-Path $Root "logs") | Out-Null
    Start-Transcript -Path (Join-Path $Root "logs\resume.log") -Append | Out-Null
    # Задача удаляется после успеха. Если Windows перезагрузится посреди доделки (после включения
    # Hyper-V бывает две перезагрузки), задача сработает снова. Но не больше 3 раз — без зацикливания.
    $attempt = 1 + [int](Get-Content $AttemptsFile -ErrorAction SilentlyContinue)
    Set-Content $AttemptsFile $attempt
    Write-Host "Продолжение после перезагрузки, попытка $attempt из 3"
    if ($attempt -ge 3) {
        Unregister-ScheduledTask -TaskName $ResumeTask -Confirm:$false -ErrorAction SilentlyContinue
    }
}

function Complete-Resume {
    if (-not $Resume) { return }
    Unregister-ScheduledTask -TaskName $ResumeTask -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item $AttemptsFile -ErrorAction SilentlyContinue
}

function Write-ResultNote([string]$text) {
    if (-not $Resume) { return }
    try {
        $stamp = Get-Date -Format "yyyy-MM-dd HH:mm"
        "[$stamp] $text`r`n`r`nПодробный лог: $(Join-Path $Root 'logs\resume.log')" |
            Set-Content -Path $ResultNote -Encoding UTF8
    } catch {}
}

function Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Ok($msg) { Write-Host "    $msg" -ForegroundColor Green }
function Warn($msg) { Write-Host "    ВНИМАНИЕ: $msg" -ForegroundColor Yellow }
function Fail($msg) {
    Write-Host "`nОШИБКА: $msg" -ForegroundColor Red
    Write-Host "Ничего не изменено на этом шаге."
    if ($Resume -and $attempt -lt 3) {
        Write-Host "Попробую ещё раз при следующей загрузке."
        Write-ResultNote "wg-panel: попытка $attempt из 3 доделать установку не удалась:`r`n$msg`r`n`r`nПерезагрузи сервер ещё раз — установка попробует снова."
    } else {
        Write-ResultNote "ОШИБКА при продолжении установки wg-panel после перезагрузки:`r`n$msg"
        Complete-Resume
    }
    if ($Resume) { Stop-Transcript | Out-Null }
    exit 1
}

function Test-WinNat {
    # Без компонентов Hyper-V классы WinNAT отсутствуют и Get-NetNat падает с «Недопустимый класс».
    try { Get-NetNat -ErrorAction Stop | Out-Null; return $true } catch { return $false }
}

function New-Password {
    $chars = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    $bytes = New-Object byte[] 16
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    return -join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })
}

function ConvertTo-UInt32([string]$ip) {
    $b = ([Net.IPAddress]::Parse($ip)).GetAddressBytes()
    [Array]::Reverse($b)
    return [BitConverter]::ToUInt32($b, 0)
}

function Test-InSubnet([string]$ip, [string]$cidr) {
    $net, $bits = $cidr.Split("/")
    $all = [uint64]4294967295  # не 0xFFFFFFFF: в PS 5.1 это Int32 = -1
    $mask = [uint32](($all -shl (32 - [int]$bits)) -band $all)
    return ((ConvertTo-UInt32 $ip) -band $mask) -eq ((ConvertTo-UInt32 $net) -band $mask)
}

# ---------------------------------------------------------------- прошлая установка
# При повторном запуске (обновлении) берём порты/подсеть/адрес из прошлой установки,
# если их явно не передали — чтобы не сломать уже выданные клиентам конфиги.
$SettingsFile = Join-Path $Data "settings.json"
$Existing = $null
if (Test-Path $SettingsFile) {
    $Existing = Get-Content $SettingsFile -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not $PSBoundParameters.ContainsKey("Endpoint"))  { $Endpoint  = $Existing.endpoint_host }
    if (-not $PSBoundParameters.ContainsKey("WgPort"))    { $WgPort    = [int]$Existing.listen_port }
    if (-not $PSBoundParameters.ContainsKey("PanelPort")) { $PanelPort = [int]$Existing.panel_port }
    if (-not $PSBoundParameters.ContainsKey("Subnet"))    { $Subnet    = $Existing.subnet }
}
$NeedPassword = -not ($Existing -and $Existing.admin_password_hash)

# ---------------------------------------------------------------- проверки
$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail "Запусти PowerShell от имени администратора."
}

Step "Проверки (ничего не меняется)"

$rdpPort = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp').PortNumber
Ok "RDP слушает порт $rdpPort — скрипт его не трогает."
if ($WgPort -eq $rdpPort -or $PanelPort -eq $rdpPort) { Fail "Порт совпадает с портом RDP ($rdpPort)." }

$WinSW = Join-Path $Root "tools\winsw.exe"
if (-not (Test-Path $WinSW)) { Fail "Не найден $WinSW (он входит в состав установщика)." }
$net = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -ErrorAction SilentlyContinue).Release
if (-not $net -or $net -lt 394254) { Fail "Нужен .NET Framework 4.6.1+ (в Windows 10 он есть по умолчанию)." }
Ok ".NET Framework 4.x есть."

$panelExists = [bool](Get-Service $PanelService -ErrorAction SilentlyContinue)
$tunnelExists = [bool](Get-Service $TunnelService -ErrorAction SilentlyContinue)

$busy = Get-NetTCPConnection -LocalPort $PanelPort -State Listen -ErrorAction SilentlyContinue
if ($busy -and -not $panelExists) {
    $p = Get-Process -Id $busy[0].OwningProcess -ErrorAction SilentlyContinue
    Fail "TCP-порт $PanelPort уже занят ($($p.ProcessName)). Выбери другой: -PanelPort 9443"
}
Ok "TCP $PanelPort для панели свободен."

$busyUdp = Get-NetUDPEndpoint -LocalPort $WgPort -ErrorAction SilentlyContinue
if ($busyUdp -and -not $tunnelExists) { Fail "UDP-порт $WgPort уже занят. Выбери другой: -WgPort 51821" }
Ok "UDP $WgPort для WireGuard свободен."

foreach ($a in (Get-NetIPAddress -AddressFamily IPv4)) {
    if ($a.InterfaceAlias -ne $Iface -and (Test-InSubnet $a.IPAddress $Subnet)) {
        Fail "Подсеть $Subnet пересекается с адресом $($a.IPAddress) на '$($a.InterfaceAlias)'. Выбери другую: -Subnet 10.66.0.0/24"
    }
}
Ok "Подсеть $Subnet ни с чем не пересекается."

$WinEdition = (Get-CimInstance Win32_OperatingSystem).Caption
Ok "Windows: $WinEdition"
$HasWinNat = Test-WinNat
$HyperVFeature = $null
$NoNatPossible = $false
if (-not $HasWinNat) {
    $HyperVFeature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -ErrorAction SilentlyContinue
    if (-not $HyperVFeature) {
        $NoNatPossible = $true
        Warn "В '$WinEdition' нет компонентов Hyper-V (так бывает в Home) — NAT включить НЕ получится."
        Warn "VPN заработает, но у клиентов НЕ будет интернета через сервер. Нужна Windows 10 Pro или выше."
    } else {
        Ok "NAT (WinNAT) пока недоступен — будут включены компоненты Hyper-V, нужна одна перезагрузка."
    }
}
$nats = @(Get-NetNat -ErrorAction SilentlyContinue)
$otherNat = $nats | Where-Object { $_.Name -ne $NatName }
if ($otherNat) {
    Warn "Уже есть NAT '$($otherNat[0].Name)' ($($otherNat[0].InternalIPInterfaceAddressPrefix)). Windows допускает только один — NAT для VPN создан НЕ будет (клиенты подключатся, но без интернета). Существующий NAT не трогаем."
}

if (-not $Endpoint) {
    try { $Endpoint = (Invoke-RestMethod -UseBasicParsing -TimeoutSec 10 "https://api.ipify.org").Trim() } catch {}
    if (-not $Endpoint) { Fail "Не удалось определить внешний IP. Укажи: -Endpoint 1.2.3.4" }
}
Ok "Адрес для клиентов: ${Endpoint}:$WgPort"

Write-Host "`nБудет сделано:"
Write-Host "  - установлен WireGuard (если нет) и Python (если нет)"
Write-Host "  - создан туннель $Iface ($Subnet), служба $TunnelService"
if ($NoNatPossible) {
    Write-Host "  - NAT: НЕ будет (нет Hyper-V в этой редакции) — клиенты без интернета через сервер" -ForegroundColor Yellow
} else {
    Write-Host "  - NAT '$NatName' для $Subnet"
}
if (-not $HasWinNat -and $HyperVFeature) {
    Write-Host "  - включены компоненты Hyper-V (сам гипервизор НЕ запускается), затем ПЕРЕЗАГРУЗКА;"
    Write-Host "    после неё установка продолжится сама (итог — файлом на рабочем столе)"
}
Write-Host "  - правила фаервола (группа '$FwGroup'): UDP $WgPort и TCP $PanelPort — только разрешающие"
Write-Host "  - служба '$PanelService', панель: https://${Endpoint}:$PanelPort"
if ($Existing) { Write-Host "  (обновление: ключи сервера и клиенты сохраняются)" }
if (-not $Yes -and (Read-Host "`nПродолжить? (y/n)") -ne "y") { exit 0 }

# ---------------------------------------------------------------- WireGuard
Step "WireGuard"
if (-not (Test-Path "$WgDir\wireguard.exe")) {
    $index = (Invoke-WebRequest -UseBasicParsing "https://download.wireguard.com/windows-client/").Content
    $versions = [regex]::Matches($index, 'wireguard-amd64-([0-9.]+)\.msi') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique { [version]$_ }
    $ver = $versions | Select-Object -Last 1
    if (-not $ver) { Fail "Не удалось найти MSI WireGuard." }
    $msi = Join-Path $env:TEMP "wireguard-amd64-$ver.msi"
    Invoke-WebRequest -UseBasicParsing "https://download.wireguard.com/windows-client/wireguard-amd64-$ver.msi" -OutFile $msi
    $p = Start-Process msiexec.exe -ArgumentList "/i `"$msi`" DO_NOT_LAUNCH=1 /qn /norestart" -Wait -PassThru
    if ($p.ExitCode -ne 0) { Fail "Установка WireGuard завершилась с кодом $($p.ExitCode)." }
    Ok "Установлен WireGuard $ver"
} else { Ok "Уже установлен." }

# ---------------------------------------------------------------- Python
Step "Python"
function Find-Python {
    foreach ($c in @(Get-ChildItem "C:\Program Files\Python3*\python.exe" -ErrorAction SilentlyContinue | Sort-Object FullName -Descending)) {
        return $c.FullName
    }
    if (Get-Command py -ErrorAction SilentlyContinue) {
        $exe = & py -3 -c "import sys;print(sys.executable)" 2>$null
        if ($LASTEXITCODE -eq 0 -and $exe) { return $exe.Trim() }
    }
    return $null
}
$Py = Find-Python
if (-not $Py) {
    $inst = Join-Path $env:TEMP "python-3.12.10-amd64.exe"
    Invoke-WebRequest -UseBasicParsing "https://www.python.org/ftp/python/3.12.10/python-3.12.10-amd64.exe" -OutFile $inst
    $p = Start-Process $inst -ArgumentList "/quiet InstallAllUsers=1 PrependPath=0 Include_test=0" -Wait -PassThru
    if ($p.ExitCode -ne 0) { Fail "Установка Python завершилась с кодом $($p.ExitCode)." }
    $Py = Find-Python
    if (-not $Py) { Fail "Python установлен, но не найден." }
}
$pyVer = & $Py -c "import sys;print('%d.%d' % sys.version_info[:2])"
if ([version]$pyVer -lt [version]"3.10") { Fail "Нужен Python 3.10+, найден $pyVer ($Py)." }
Ok "Python $pyVer — $Py"

$VenvPy = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $VenvPy)) { & $Py -m venv (Join-Path $Root ".venv") }
& $VenvPy -m pip install --disable-pip-version-check -q -r (Join-Path $Root "requirements.txt")
if ($LASTEXITCODE -ne 0) { Fail "pip install не удался." }
Ok "Зависимости установлены."

# ---------------------------------------------------------------- данные и конфиг
Step "Настройка панели"
New-Item -ItemType Directory -Force $Data, $Logs | Out-Null
# Ключи лежат в data — доступ только Администраторам и SYSTEM (SID, чтобы работало на русской Windows)
& icacls $Data /inheritance:r /grant:r "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" | Out-Null

$GeneratedPassword = $null
if ($NeedPassword -and -not $AdminPassword -and $Yes) {
    $AdminPassword = New-Password
    $GeneratedPassword = $AdminPassword
}
Push-Location $Root
try {
    # пароль передаём через окружение, а не аргументом (не светится в списке процессов)
    if ($NeedPassword -and $AdminPassword) { $env:WGPANEL_ADMIN_PASSWORD = $AdminPassword }
    & $VenvPy -m app.init_panel --endpoint $Endpoint --listen-port $WgPort --panel-port $PanelPort --subnet $Subnet
    if ($LASTEXITCODE -ne 0) { Fail "Инициализация панели не удалась." }
} finally {
    Remove-Item Env:\WGPANEL_ADMIN_PASSWORD -ErrorAction SilentlyContinue
    Pop-Location
}

# ---------------------------------------------------------------- туннель
Step "Туннель $Iface"
if (-not $tunnelExists) {
    & "$WgDir\wireguard.exe" /installtunnelservice (Join-Path $Data "wg0.conf")
    Ok "Служба туннеля установлена."
} else {
    Ok "Служба туннеля уже есть — пиры синхронизирует панель."
}
$up = $false
$waitUp = if ($Resume) { 120 } else { 30 }  # сразу после загрузки туннель стартует дольше
for ($i = 0; $i -lt $waitUp; $i++) {
    if (Get-NetAdapter -Name $Iface -ErrorAction SilentlyContinue) { $up = $true; break }
    Start-Sleep 1
}
if (-not $up) { Fail "Интерфейс $Iface не поднялся. Смотри журнал: `"$WgDir\wireguard.exe`" /dumplog" }
Ok "Интерфейс $Iface поднят."

# ---------------------------------------------------------------- NAT / forwarding
Step "NAT и маршрутизация"
$RebootNeeded = $false
if (-not $HasWinNat -and $HyperVFeature -and -not $otherNat) {
    if ($Resume) {
        Fail "После перезагрузки WinNAT так и не появился. Проверь: Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All"
    }
    Ok "Включаю компоненты Hyper-V (1–3 минуты)..."
    # /all тянет и сам гипервизор — это нормально, ниже его запуск отключается.
    & dism.exe /online /enable-feature /featurename:Microsoft-Hyper-V-All /all /norestart /quiet
    $code = $LASTEXITCODE
    if ($code -ne 0 -and $code -ne 3010) {  # 3010 = успешно, нужна перезагрузка
        # На VPS без аппаратной виртуализации DISM может отказаться ставить сам гипервизор.
        # Для NAT он не нужен — пробуем только службы Hyper-V.
        Warn "Полный Hyper-V не включился (код $code), пробую без гипервизора..."
        & dism.exe /online /enable-feature /featurename:Microsoft-Hyper-V-All /featurename:Microsoft-Hyper-V `
            /featurename:Microsoft-Hyper-V-Services /featurename:Microsoft-Hyper-V-Management-PowerShell /norestart /quiet
        $code = $LASTEXITCODE
    }
    if ($code -ne 0 -and $code -ne 3010) {
        Fail "DISM не смог включить компоненты Hyper-V (код $code). Лог: C:\Windows\Logs\DISM\dism.log"
    }
    # Гипервизор не запускаем: NAT работает и без него, а на VPS без вложенной виртуализации
    # попытка его запуска не нужна.
    & bcdedit.exe /set hypervisorlaunchtype off | Out-Null
    if ($LASTEXITCODE -ne 0) { Warn "bcdedit /set hypervisorlaunchtype off не удался (код $LASTEXITCODE)." }
    Ok "Компоненты Hyper-V включены, запуск гипервизора отключён."

    # Изменение загрузчика при включённом BitLocker = запрос ключа восстановления при загрузке.
    # На VPS без консоли это потеря доступа, поэтому приостанавливаем защиту на одну перезагрузку.
    try {
        $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
        if ($bl.ProtectionStatus -eq "On") {
            Suspend-BitLocker -MountPoint $env:SystemDrive -RebootCount 1 | Out-Null
            Ok "BitLocker приостановлен на одну перезагрузку (иначе Windows спросит ключ восстановления)."
        }
    } catch {}

    $action = New-ScheduledTaskAction -Execute "powershell.exe" `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$(Join-Path $Root 'install.ps1')`" -Resume"
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $trigger.Delay = "PT30S"  # дать сети и службам подняться
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 1) -StartWhenAvailable
    Remove-Item $AttemptsFile -ErrorAction SilentlyContinue  # счётчик попыток — с нуля
    Register-ScheduledTask -TaskName $ResumeTask -Action $action -Trigger $trigger -Principal $principal `
        -Settings $settings -Force | Out-Null
    Ok "После перезагрузки установка продолжится сама (задача '$ResumeTask')."
    $RebootNeeded = $true
} elseif ($NoNatPossible) {
    Warn "NAT пропущен: в '$WinEdition' нет Hyper-V. Клиенты подключатся, но без интернета через сервер."
} elseif (-not $otherNat) {
    if (-not (Get-NetNat -Name $NatName -ErrorAction SilentlyContinue)) {
        try {
            New-NetNat -Name $NatName -InternalIPInterfaceAddressPrefix $Subnet | Out-Null
            Ok "NAT '$NatName' создан."
        } catch {
            Warn "New-NetNat не сработал: $($_.Exception.Message)"
            Warn "Клиенты подключатся, но без интернета через сервер."
        }
    } else { Ok "NAT уже есть." }
}
try { Set-NetIPInterface -InterfaceAlias $Iface -AddressFamily IPv4 -Forwarding Enabled } catch { Warn $_.Exception.Message }
Ok "Forwarding включён на $Iface (панель переприменяет его после перезагрузок)."

# ---------------------------------------------------------------- фаервол
Step "Фаервол (только добавляем разрешающие правила)"
$rules = @(
    @{ Name = "wg-panel-udp"; Display = "WireGuard UDP $WgPort"; Proto = "UDP"; Port = $WgPort },
    @{ Name = "wg-panel-web"; Display = "WireGuard panel TCP $PanelPort"; Proto = "TCP"; Port = $PanelPort }
)
foreach ($r in $rules) {
    Remove-NetFirewallRule -Name $r.Name -ErrorAction SilentlyContinue  # наше же правило — обновляем порт
    New-NetFirewallRule -Name $r.Name -DisplayName $r.Display -Group $FwGroup -Direction Inbound `
        -Protocol $r.Proto -LocalPort $r.Port -Action Allow -Profile Any | Out-Null
    Ok "$($r.Display)"
}

# ---------------------------------------------------------------- служба панели
Step "Служба $PanelService"
# WinSW: exe-обёртка + xml рядом с ним с тем же именем
$SvcDir = Join-Path $Root "service"
$SvcExe = Join-Path $SvcDir "$PanelService.exe"
$SvcXml = Join-Path $SvcDir "$PanelService.xml"
New-Item -ItemType Directory -Force $SvcDir | Out-Null

if ($panelExists) {
    Stop-Service $PanelService -Force -ErrorAction SilentlyContinue  # чтобы можно было заменить exe
    Start-Sleep 2
}
if (-not (Test-Path $SvcExe) -or (Get-FileHash $SvcExe).Hash -ne (Get-FileHash $WinSW).Hash) {
    Copy-Item $WinSW $SvcExe -Force
}
$esc = { param($v) [Security.SecurityElement]::Escape($v) }
@"
<service>
  <id>$PanelService</id>
  <name>WireGuard Panel</name>
  <description>Веб-панель управления WireGuard ($(& $esc $Root))</description>
  <executable>$(& $esc $VenvPy)</executable>
  <arguments>"$(& $esc (Join-Path $Root 'run.py'))"</arguments>
  <workingdirectory>$(& $esc $Root)</workingdirectory>
  <startmode>Automatic</startmode>
  <onfailure action="restart" delay="10 sec"/>
  <resetfailure>1 hour</resetfailure>
  <logpath>$(& $esc $Logs)</logpath>
  <log mode="roll-by-size">
    <sizeThreshold>5120</sizeThreshold>
    <keepFiles>5</keepFiles>
  </log>
</service>
"@ | Set-Content -Path $SvcXml -Encoding UTF8

if (-not $panelExists) {
    & $SvcExe install | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "Не удалось зарегистрировать службу $PanelService." }
}
Start-Service $PanelService

# ждём, пока панель реально начнёт принимать соединения
$listening = $false
for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep 1
    try {
        $tcp = New-Object Net.Sockets.TcpClient
        $tcp.Connect("127.0.0.1", $PanelPort)
        $tcp.Close()
        $listening = $true
        break
    } catch {}
}
if (-not $listening) { Fail "Служба запущена, но панель не отвечает на порту $PanelPort. Смотри логи в $Logs" }
Ok "Панель отвечает на порту $PanelPort."

Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host " Готово!" -ForegroundColor Green
Write-Host " Панель:  https://${Endpoint}:$PanelPort"
Write-Host "          (сертификат самоподписанный — браузер предупредит, это нормально)"
if ($GeneratedPassword) {
    Write-Host " Пароль:  $GeneratedPassword" -ForegroundColor Yellow
    Write-Host "          (сохрани его; сменить: .venv\Scripts\python -m app.init_panel --set-password)"
}
Write-Host " Папка:   $Root"
Write-Host " Если у хостера есть свой фаервол — открой там UDP $WgPort и TCP $PanelPort."
if ($NoNatPossible -or $otherNat) {
    Write-Host ""
    Write-Host " ВНИМАНИЕ: NAT не настроен — у клиентов НЕ будет интернета через сервер." -ForegroundColor Yellow
    if ($NoNatPossible) { Write-Host " Причина: в '$WinEdition' нет Hyper-V (нужна Pro или выше)." -ForegroundColor Yellow }
    else { Write-Host " Причина: в системе уже есть другой NAT ('$($otherNat[0].Name)'), а Windows допускает только один." -ForegroundColor Yellow }
}
if ($RebootNeeded) {
    Write-Host ""
    Write-Host " Для интернета у клиентов (NAT) нужна ПЕРЕЗАГРУЗКА." -ForegroundColor Yellow
    Write-Host " После неё установка доделается сама примерно через минуту;" -ForegroundColor Yellow
    Write-Host " итог появится файлом на рабочем столе: '$(Split-Path $ResultNote -Leaf)'." -ForegroundColor Yellow
}
Write-Host "================================================================" -ForegroundColor Green

if ($Resume) {
    Complete-Resume
    Write-ResultNote "wg-panel: установка завершена, NAT работает.`r`nПанель: https://${Endpoint}:$PanelPort"
    Stop-Transcript | Out-Null
} elseif ($RebootNeeded) {
    if ($Yes) {
        Write-Host "`nПерезагрузка через 30 секунд (RDP отключится, переподключись через пару минут)..." -ForegroundColor Yellow
        & shutdown.exe /r /t 30 /c "wg-panel: перезагрузка для включения NAT"
    } elseif ((Read-Host "`nПерезагрузить сейчас? RDP отключится на пару минут (y/n)") -eq "y") {
        Restart-Computer -Force
    } else {
        Write-Host "Хорошо. Установка продолжится сама при следующей перезагрузке."
    }
}
