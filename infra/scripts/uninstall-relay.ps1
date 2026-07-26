#Requires -RunAsAdministrator
<#
  uninstall-relay.ps1 — remove a Gotham mixnet relay installed by
  install-relay.ps1 on Windows: the "GothamRelay" Scheduled Task, the
  C:\ProgramData\Gotham folder, the firewall rule, and the machine
  enrollment-token env var. Reverses exactly what the installer created.

  Run in an ELEVATED PowerShell (Run as Administrator):
    irm https://raw.githubusercontent.com/0x9Angel/gotham-relay/main/infra/scripts/uninstall-relay.ps1 | iex

  By default this removes EVERYTHING, including the identity key (a reinstall
  gets a NEW public key). To keep the key for a same-identity reinstall:
    $env:GOTHAM_KEEP_KEYS='1'; irm https://raw.githubusercontent.com/0x9Angel/gotham-relay/main/infra/scripts/uninstall-relay.ps1 | iex
#>
$ErrorActionPreference = "Continue"

$Task     = "GothamRelay"
$Dir      = Join-Path $env:ProgramData "Gotham"
$Key      = Join-Path $Dir "relay.key"
$KeepKeys = ($env:GOTHAM_KEEP_KEYS -eq '1')

Write-Host "[1/5] Stopping + removing the scheduled task ($Task)..."
Stop-ScheduledTask       -TaskName $Task -ErrorAction SilentlyContinue | Out-Null
Unregister-ScheduledTask -TaskName $Task -Confirm:$false -ErrorAction SilentlyContinue

Write-Host "[2/5] Killing any running relay process (releases the .exe lock)..."
Get-Process -Name "gotham-relay" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

Write-Host "[3/5] Removing the firewall rule(s)..."
Get-NetFirewallRule -DisplayName "Gotham QUIC relay*" -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule -ErrorAction SilentlyContinue

Write-Host "[4/5] Removing the machine enrollment-token env var (if any)..."
[Environment]::SetEnvironmentVariable("GOTHAM_ENROLL_TOKEN", $null, "Machine")

Write-Host "[5/5] Removing files..."
if ($KeepKeys -and (Test-Path $Key)) {
    # Preserve the identity key; delete everything else in the folder. Retry a
    # couple of times in case the .exe handle is still being released after the
    # process was killed in step 2.
    for ($i = 0; $i -lt 3; $i++) {
        Get-ChildItem -Path $Dir -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -ne $Key } |
            Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        $rest = Get-ChildItem -Path $Dir -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -ne $Key }
        if (-not $rest) { break }
        Start-Sleep -Seconds 1
    }
    Write-Host "    Kept identity key: $Key"
} else {
    # Retry a couple of times in case a file handle is still being released.
    for ($i = 0; $i -lt 3; $i++) {
        Remove-Item -Path $Dir -Recurse -Force -ErrorAction SilentlyContinue
        if (-not (Test-Path $Dir)) { break }
        Start-Sleep -Seconds 1
    }
}

Write-Host ""
Write-Host "============================================================"
# Report accurately in BOTH branches: in keep-keys mode the identity key is an
# expected leftover; anything else means a file could not be removed.
$leftover = @()
if (Test-Path $Dir) {
    $leftover = @(Get-ChildItem -Path $Dir -Force -ErrorAction SilentlyContinue |
        Where-Object { -not ($KeepKeys -and $_.FullName -eq $Key) })
}
if ($leftover.Count -gt 0) {
    Write-Host " Task + firewall + token removed, but some files under $Dir could"
    Write-Host " not be deleted (a file may still be locked). Reboot, then run:"
    if ($KeepKeys) { Write-Host "   Get-ChildItem '$Dir' -Exclude relay.key | Remove-Item -Recurse -Force" }
    else           { Write-Host "   Remove-Item '$Dir' -Recurse -Force" }
} else {
    Write-Host " Gotham relay UNINSTALLED."
    if ($KeepKeys) { Write-Host " Identity key kept at $Key (a reinstall reuses it)." }
}
Write-Host "============================================================"
