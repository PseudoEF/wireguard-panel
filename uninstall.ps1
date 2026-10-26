<#
  Удаляет только то, что поставил install.ps1:
  службу wg-panel, туннель wg0, NAT "wgpanel", правила фаервола группы "wg-panel".
  Папка data (ключи, клиенты) сохраняется, если не указан -PurgeData.
  Сам WireGuard и Python не удаляются. Компоненты Hyper-V (если их включал установщик)
  тоже остаются — они ничему не мешают; вернуть как было:
    dism /online /disable-feature /featurename:Microsoft-Hyper-V-All /norestart
    bcdedit /set hypervisorlaunchtype auto
#>
param([switch]$PurgeData)

$ErrorActionPreference = "Continue"
$Root = $PSScriptRoot
$SvcExe = Join-Path $Root "service\wg-panel.exe"

if (Get-Service "wg-panel" -ErrorAction SilentlyContinue) {
    Stop-Service "wg-panel" -Force
    if (Test-Path $SvcExe) { & $SvcExe uninstall | Out-Null } else { & sc.exe delete "wg-panel" | Out-Null }
    Write-Host "Служба wg-panel удалена."
}
if (Get-ScheduledTask -TaskName "wg-panel-resume" -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName "wg-panel-resume" -Confirm:$false
    Write-Host "Задача wg-panel-resume удалена."
}
if (Get-Service 'WireGuardTunnel$wg0' -ErrorAction SilentlyContinue) {
    & "C:\Program Files\WireGuard\wireguard.exe" /uninstalltunnelservice wg0
    Write-Host "Туннель wg0 удалён."
}
if (Get-NetNat -Name "wgpanel" -ErrorAction SilentlyContinue) {
    Remove-NetNat -Name "wgpanel" -Confirm:$false
    Write-Host "NAT wgpanel удалён."
}
Get-NetFirewallRule -Group "wg-panel" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
Write-Host "Правила фаервола wg-panel удалены."

if ($PurgeData) {
    Remove-Item -Recurse -Force (Join-Path $Root "data")
    Write-Host "Папка data удалена."
}
