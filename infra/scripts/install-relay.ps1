#Requires -RunAsAdministrator
<#
  install-relay.ps1 — one-command Gotham mixnet relay installer for Windows.

  Downloads the checksum-verified relay .exe, generates an identity key, and
  registers a Scheduled Task that launches the relay IN THE BACKGROUND AT EVERY
  BOOT (as SYSTEM, before login, no window) with auto-restart on failure — so
  after the PC is shut down and turned back on, the relay comes back on its own.
  Opens the Windows Firewall for the UDP port.

  Run in an ELEVATED PowerShell (no token needed, enrollment is open):
    irm https://raw.githubusercontent.com/0x9Angel/gotham-relay/main/infra/scripts/install-relay.ps1 | iex

  Env vars (all optional; same as the Linux/macOS installers):
    GOTHAM_ENROLL_TOKEN  Only if the authority runs in closed/token mode.
                         Enrollment is OPEN by default - you do NOT need one.
    GOTHAM_AUTHORITY_URL default http://144.24.205.188:8443
    GOTHAM_TIER          entry|mix|exit (default mix)
    GOTHAM_PORT          default 443
    GOTHAM_ADVERTISE_IP  optional; if unset the relay auto-maps its port and
                         detects its public IP via UPnP-IGD (home routers).
    GOTHAM_RENDEZVOUS    auto | on | off. Default auto: enrol via a rendezvous
                         point (RFC B3) when no reachable public address is
                         found - lets a Windows box on 4G/5G / CGNAT be a relay.
#>
$ErrorActionPreference = "Stop"

$Repo    = "0x9Angel/gotham-relay"
$Token   = $env:GOTHAM_ENROLL_TOKEN
$AuthUrl = if ($env:GOTHAM_AUTHORITY_URL) { $env:GOTHAM_AUTHORITY_URL } else { "http://144.24.205.188:8443" }
$Tier    = if ($env:GOTHAM_TIER) { $env:GOTHAM_TIER } else { "mix" }
$Port    = if ($env:GOTHAM_PORT) { $env:GOTHAM_PORT } else { "443" }

if (@("entry", "mix", "exit") -notcontains $Tier) { throw "GOTHAM_TIER must be entry|mix|exit (got '$Tier')" }

$Dir = Join-Path $env:ProgramData "Gotham"
$Bin = Join-Path $Dir "gotham-relay.exe"
$Key = Join-Path $Dir "relay.key"
New-Item -ItemType Directory -Force -Path $Dir | Out-Null

Write-Host "[1/5] Downloading + verifying binary..."
$Asset = "gotham-relay-windows-x86_64.exe"
$Base  = "https://github.com/$Repo/releases/latest/download"
Invoke-WebRequest -Uri "$Base/$Asset"        -OutFile $Bin
Invoke-WebRequest -Uri "$Base/$Asset.sha256" -OutFile "$Bin.sha256"
$expected = ((Get-Content "$Bin.sha256") -split '\s+')[0].ToLower()
$actual   = (Get-FileHash $Bin -Algorithm SHA256).Hash.ToLower()
if ($expected -ne $actual) { Remove-Item $Bin -Force; throw "Checksum verification FAILED - refusing to install." }

Write-Host "[2/5] Generating relay identity (if absent)..."
if (-not (Test-Path $Key)) { & $Bin keygen --key-file $Key | Out-Null }
$PubKey = (& $Bin pubkey --key-file $Key)

Write-Host "[3/5] Determining reachability (direct vs rendezvous)..."
# Public IP (best-effort). Not fatal: a CGNAT box has no reachable public address
# and falls back to a rendezvous point (RFC B3) below.
$AdvIp = $env:GOTHAM_ADVERTISE_IP
if (-not $AdvIp) {
    try   { $AdvIp = (Invoke-RestMethod -Uri "https://api.ipify.org" -TimeoutSec 8).ToString().Trim() }
    catch { $AdvIp = $null }
}

# Decide DIRECT (we have a reachable public address) vs RENDEZVOUS (behind CGNAT
# / mobile 4G-5G / broken UPnP: keep an OUTBOUND tunnel to a public rendezvous
# relay, no inbound reachability needed). GOTHAM_RENDEZVOUS=on|off|auto.
$Rdv = if ($env:GOTHAM_RENDEZVOUS) { $env:GOTHAM_RENDEZVOUS.ToLower() } else { "auto" }
if ($Rdv -in @("on", "1", "true")) {
    $Mode = "rendezvous"
} elseif ($Rdv -in @("off", "0", "false")) {
    $Mode = "direct"
} elseif ($env:GOTHAM_ADVERTISE_IP) {
    $Mode = "direct"                                    # operator asserts a reachable address
} elseif ($AdvIp -and ((Get-NetIPAddress -ErrorAction SilentlyContinue).IPAddress -contains $AdvIp)) {
    $Mode = "direct"                                    # our public IP is bound to a local interface
} else {
    $Mode = "rendezvous"                                # no public IP on this host -> behind NAT/CGNAT
}

if ($Mode -eq "rendezvous") {
    Write-Host "    No reachable public address - enrolling via a RENDEZVOUS point (RFC B3, works behind CGNAT/4G-5G)."
    try   { $dir = Invoke-RestMethod -Uri "$AuthUrl/directory" -TimeoutSec 10 } catch { $dir = $null }
    $rp = if ($dir) { $dir.doc.relays | Where-Object { $_.rendezvous_capable } | Select-Object -First 1 } else { $null }
    if (-not $rp) {
        throw "No rendezvous point available from $AuthUrl. An operator must run a public relay with --rendezvous-capable, or set `$env:GOTHAM_ADVERTISE_IP='<reachable.ip>' if you can port-forward UDP $Port."
    }
    Write-Host "    Rendezvous relay: $($rp.addr)"
    # No --advertise-addr in rendezvous mode (a CGNAT relay has no dialable
    # address); the authority PoP key is auto-fetched from /pop.
    $binArgs = @(
        "run", "--key-file", $Key,
        "--listen-host", "0.0.0.0", "--listen-port", $Port,
        "--authority-url", $AuthUrl, "--tier", $Tier, "--heartbeat-secs", "60",
        "--rendezvous-key", $rp.kem_pubkey_hex, "--rendezvous-addr", $rp.addr
    )
    $AdvMsg = "via rendezvous $($rp.addr) (CGNAT/B3)"
} else {
    if (-not $AdvIp) {
        throw "Could not detect a public IP (api.ipify.org unreachable). Re-run with `$env:GOTHAM_ADVERTISE_IP='<your.public.ip>', or `$env:GOTHAM_RENDEZVOUS='on' to use a rendezvous point."
    }
    Write-Host "    Directly reachable - advertising $($AdvIp):$Port/udp."
    $binArgs = @(
        "run", "--key-file", $Key,
        "--listen-host", "0.0.0.0", "--listen-port", $Port,
        "--authority-url", $AuthUrl, "--tier", $Tier, "--heartbeat-secs", "60",
        "--advertise-addr", "$($AdvIp):$Port"
    )
    $AdvMsg = "$($AdvIp):$Port"
}

# Token (only in closed/token mode) via a MACHINE env var so it is not visible
# in the task's command line. Open enrollment needs none.
if ($Token) { [Environment]::SetEnvironmentVariable("GOTHAM_ENROLL_TOKEN", $Token, "Machine") }

Write-Host "[4/5] Registering boot Scheduled Task (SYSTEM, background, auto-restart)..."
$action    = New-ScheduledTaskAction -Execute $Bin -Argument ($binArgs -join " ")
$trigger   = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable -MultipleInstances IgnoreNew `
    -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit (New-TimeSpan -Seconds 0)
Unregister-ScheduledTask -TaskName "GothamRelay" -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName "GothamRelay" -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings `
    -Description "Gotham mixnet relay - auto-starts in the background at boot" | Out-Null

Write-Host "[5/5] Firewall + start now..."
# Rendezvous mode is OUTBOUND-only - no inbound port to open. Only open UDP when
# we advertise a directly-reachable address.
if ($Mode -eq "direct") {
    New-NetFirewallRule -DisplayName "Gotham QUIC relay (UDP $Port)" -Direction Inbound `
        -Protocol UDP -LocalPort $Port -Action Allow -ErrorAction SilentlyContinue | Out-Null
}
Start-ScheduledTask -TaskName "GothamRelay"

Write-Host ""
Write-Host "============================================================"
Write-Host " Gotham relay installed - starts automatically at every boot,"
Write-Host " in the background (Scheduled Task: GothamRelay)."
Write-Host " Public key : $PubKey"
Write-Host " Reachable  : $AdvMsg   (tier: $Tier, port $Port/udp)"
Write-Host " Authority  : $AuthUrl"
Write-Host " Status     : Get-ScheduledTask GothamRelay | Get-ScheduledTaskInfo"
Write-Host " Stop/Start : Stop-ScheduledTask GothamRelay  /  Start-ScheduledTask GothamRelay"
Write-Host " Uninstall  : irm https://raw.githubusercontent.com/$Repo/main/infra/scripts/uninstall-relay.ps1 | iex"
Write-Host "============================================================"
Write-Host ""
if ($Mode -eq "rendezvous") {
    Write-Host " RENDEZVOUS mode (RFC B3): outbound-only tunnel to $($rp.addr) - works" -ForegroundColor Cyan
    Write-Host " behind CGNAT / 4G-5G / broken UPnP. No port-forward needed."
} else {
    Write-Host " REACHABILITY - the authority must reach you at $AdvMsg over UDP:" -ForegroundColor Cyan
    Write-Host "   * VPS / cloud:  open UDP $Port in your provider's firewall / security group."
    Write-Host "   * Home box:     forward UDP $Port on your router to this machine's LAN IP."
    Write-Host "   * Behind CGNAT / 4G-5G tethering / shared connection: re-run with"
    Write-Host "                   `$env:GOTHAM_RENDEZVOUS='on' to enrol via a rendezvous point."
}
Write-Host ""
Write-Host " Confirm you actually ENROLLED (run this now):" -ForegroundColor Cyan
Write-Host "   irm https://raw.githubusercontent.com/0x9Angel/gotham-relay/main/infra/scripts/diagnose-relay.ps1 | iex"
Write-Host "============================================================"
