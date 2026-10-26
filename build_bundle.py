"""Собирает один установочный файл dist/wg-panel-setup.ps1.

    python build_bundle.py

Внутрь (zip -> base64) упаковываются код панели, install/uninstall-скрипты и
tools/winsw.exe. На сервер нужно скопировать только получившийся .ps1.
"""

import base64
import hashlib
import io
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DIST = ROOT / "dist"
OUT = DIST / "wg-panel-setup.ps1"

INCLUDE = [
    "app",
    "run.py",
    "requirements.txt",
    "install.ps1",
    "uninstall.ps1",
    "README.md",
    "tools/winsw.exe",
    "client-tools/check-route.bat",
]
# WinSW v2.12.0, WinSW.NET461.exe с github.com/winsw/winsw/releases
WINSW_SHA256 = "b5066b7bbdfba1293e5d15cda3caaea88fbeab35bd5b38c41c913d492aadfc4f"

TEMPLATE = r'''<#
  Установщик WireGuard + веб-панели для Windows 10 — всё в одном файле.

  Как запустить:
    - правый клик по файлу -> "Выполнить с помощью PowerShell"
      (сам запросит права администратора), или
    - из PowerShell:  powershell -ExecutionPolicy Bypass -File .\wg-panel-setup.ps1

  Параметры (все необязательные):
    -InstallDir C:\wg-panel   куда ставить
    -Endpoint 1.2.3.4         внешний IP/домен сервера (по умолчанию определяется сам)
    -WgPort 51820             UDP-порт WireGuard
    -PanelPort 8443           порт веб-панели
    -Subnet 10.8.0.0/24       подсеть VPN
    -AdminPassword ...        пароль панели (иначе спросит; с -Yes — сгенерирует)
    -Yes                      без вопросов

  Повторный запуск более новой версии = обновление: ключи, клиенты и настройки сохраняются.
  Сборка: __BUILD__
#>
param(
    [string]$InstallDir = "C:\wg-panel",
    [string]$Endpoint,
    [int]$WgPort,
    [int]$PanelPort,
    [string]$Subnet,
    [string]$AdminPassword,
    [switch]$Yes
)

$ErrorActionPreference = "Stop"
$Bound = $PSBoundParameters  # внутри функции $PSBoundParameters — уже её собственные параметры

function Main {
    $me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        # перезапускаемся с правами администратора, окно не закрываем — чтобы был виден результат
        $argList = @("-NoExit", "-ExecutionPolicy", "Bypass", "-File", "`"$PSCommandPath`"")
        foreach ($k in $Bound.Keys) {
            $v = $Bound[$k]
            if ($v -is [switch]) { if ($v) { $argList += "-$k" } }
            else { $argList += "-$k"; $argList += "`"$v`"" }
        }
        Start-Process powershell.exe -Verb RunAs -ArgumentList $argList
        return
    }

    Write-Host "Распаковка в $InstallDir ..." -ForegroundColor Cyan
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $bytes = [Convert]::FromBase64String($Payload)
    $zip = New-Object IO.Compression.ZipArchive((New-Object IO.MemoryStream(, $bytes)))
    try {
        foreach ($e in $zip.Entries) {
            if ($e.FullName.EndsWith("/")) { continue }
            $dest = Join-Path $InstallDir ($e.FullName -replace "/", "\")
            New-Item -ItemType Directory -Force (Split-Path $dest) | Out-Null
            [IO.Compression.ZipFileExtensions]::ExtractToFile($e, $dest, $true)
        }
    } finally { $zip.Dispose() }

    $winsw = Join-Path $InstallDir "tools\winsw.exe"
    if ((Get-FileHash $winsw -Algorithm SHA256).Hash -ne "__WINSW_SHA256__") {
        throw "Контрольная сумма winsw.exe не совпала — установщик повреждён."
    }

    $params = @{}
    foreach ($k in $Bound.Keys) {
        if ($k -ne "InstallDir") { $params[$k] = $Bound[$k] }
    }
    & (Join-Path $InstallDir "install.ps1") @params
}

$Payload = @'
__PAYLOAD__
'@

Main
'''


def build() -> None:
    winsw = ROOT / "tools" / "winsw.exe"
    if hashlib.sha256(winsw.read_bytes()).hexdigest() != WINSW_SHA256:
        raise SystemExit("tools/winsw.exe не совпадает с ожидаемой контрольной суммой")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for item in INCLUDE:
            p = ROOT / item
            files = [p] if p.is_file() else sorted(f for f in p.rglob("*") if f.is_file())
            for f in files:
                if "__pycache__" in f.parts:
                    continue
                z.write(f, f.relative_to(ROOT).as_posix())
    data = buf.getvalue()

    b64 = base64.b64encode(data).decode()
    b64 = "\n".join(b64[i:i + 120] for i in range(0, len(b64), 120))
    build_id = hashlib.sha256(data).hexdigest()[:12]
    text = (
        TEMPLATE.replace("__PAYLOAD__", b64)
        .replace("__WINSW_SHA256__", WINSW_SHA256.upper())
        .replace("__BUILD__", build_id)
    )
    DIST.mkdir(exist_ok=True)
    # BOM обязателен: PowerShell 5.1 иначе читает файл как ANSI и ломает кириллицу.
    # CRLF — родные для Windows переводы строк.
    OUT.write_bytes(b"\xef\xbb\xbf" + text.replace("\r\n", "\n").replace("\n", "\r\n").encode("utf-8"))
    print(f"{OUT}  ({OUT.stat().st_size // 1024} КБ, сборка {build_id})")


if __name__ == "__main__":
    build()
