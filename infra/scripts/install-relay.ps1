#Requires -RunAsAdministrator
<#
  install-relay.ps1 — one-command Gotham mixnet relay installer for Windows.

  Downloads the checksum-verified relay .exe, generates an identity key, and
  registers a Scheduled Task that launches the relay IN THE BACKGROUND AT EVERY
  BOOT (as SYSTEM, before login, no window) with auto-restart on failure — so
  after the PC is shut down and turned back on, the relay comes back on its own.
  Opens the Windows Firewall for the UDP port.

  Run in an ELEVATED PowerShell (no token needed, enrollment is open, but you
  MUST name yourself so the network is allowed to route through you):
    $env:GOTHAM_OPERATOR='your-name'
    irm https://raw.githubusercontent.com/0x9Angel/gotham-relay/main/infra/scripts/install-relay.ps1 | iex

  Env vars (same as the Linux/macOS installers):
    GOTHAM_OPERATOR      REQUIRED. Public nickname identifying who runs this
                         relay. Path selection refuses two hops it cannot PROVE
                         belong to different operators, so an unlabelled relay
                         is never routed. Use the SAME value on every relay you
                         run, so diversity reflects who actually runs what.
    GOTHAM_ENROLL_TOKEN  Only if the authority runs in closed/token mode.
                         Enrollment is OPEN by default - you do NOT need one.
    GOTHAM_AUTHORITY_URL default http://144.24.205.188:8443
    GOTHAM_EXTRA_AUTHORITY_URLS
                         Space-separated ADDITIONAL authorities to enroll with.
                         Clients need a quorum of attestations, so the default is
                         the other two authorities of the shipped set.
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
# Clients admit a relay only when k of n authorities have attested it (k=2, n=3
# in the shipped app). A relay enrolled with the primary alone runs, reports
# itself healthy, and is dropped in silence by every client. Enrol with all three.
$ExtraAuthUrls = if ($env:GOTHAM_EXTRA_AUTHORITY_URLS) {
    $env:GOTHAM_EXTRA_AUTHORITY_URLS -split '\s+' | Where-Object { $_ }
} else {
    @("http://84.235.232.196:8443", "http://84.235.228.107:8443")
}
$Operator = $env:GOTHAM_OPERATOR

if (@("entry", "mix", "exit") -notcontains $Tier) { throw "GOTHAM_TIER must be entry|mix|exit (got '$Tier')" }

# Checked BEFORE anything is downloaded: a relay that cannot be routed is worse
# than no relay, because nobody finds out. Better a clean refusal now.
if (-not $Operator) {
    throw @"
GOTHAM_OPERATOR is required and was not set.

Clients refuse to build a path through two relays unless they can prove the
relays belong to DIFFERENT operators, and a relay with no operator label counts
as unproven. An unlabelled relay would run, report itself healthy, and never
carry a single packet.

Re-run with a public nickname, e.g.:
  `$env:GOTHAM_OPERATOR='your-name'
  irm https://raw.githubusercontent.com/$Repo/main/infra/scripts/install-relay.ps1 | iex

Use the SAME value on every relay you run, so the network can tell your machines
apart from everyone else's.
"@
}
# The label is passed through the Scheduled Task's single command-line string,
# so restrict it to characters that cannot become a separate argument.
if ($Operator -notmatch '^[A-Za-z0-9._-]{1,32}$') {
    throw "GOTHAM_OPERATOR must be 1 to 32 characters from A-Z a-z 0-9 . _ - (got '$Operator')"
}

$Dir = Join-Path $env:ProgramData "Gotham"
$Bin = Join-Path $Dir "gotham-relay.exe"
$Key = Join-Path $Dir "relay.key"
New-Item -ItemType Directory -Force -Path $Dir | Out-Null

Write-Host "[1/6] Downloading + verifying binary..."
$Asset = "gotham-relay-windows-x86_64.exe"
$Base  = "https://github.com/$Repo/releases/latest/download"
Invoke-WebRequest -Uri "$Base/$Asset"        -OutFile $Bin
Invoke-WebRequest -Uri "$Base/$Asset.sha256" -OutFile "$Bin.sha256"
$expected = ((Get-Content "$Bin.sha256") -split '\s+')[0].ToLower()
$actual   = (Get-FileHash $Bin -Algorithm SHA256).Hash.ToLower()
if ($expected -ne $actual) { Remove-Item $Bin -Force; throw "Checksum verification FAILED - refusing to install." }

Write-Host "[2/6] Generating relay identity (if absent)..."
if (-not (Test-Path $Key)) { & $Bin keygen --key-file $Key | Out-Null }
# One trimmed line: the enrollment check below matches this against the signed
# directory, and a stray newline or a second line would break that match.
$PubKey = (& $Bin pubkey --key-file $Key | Select-Object -First 1).ToString().Trim()

Write-Host "[3/6] Determining reachability (direct vs rendezvous)..."
# Public IP (best-effort). Not fatal: a CGNAT box has no reachable public address
# and falls back to a rendezvous point (RFC B3) below.
$AdvIp = $env:GOTHAM_ADVERTISE_IP
if (-not $AdvIp) {
    try   { $AdvIp = (Invoke-RestMethod -Uri "https://api.ipify.org" -TimeoutSec 8).ToString().Trim() }
    catch { $AdvIp = $null }
}

# Flags every relay carries whatever its transport: one --extra-authority-url per
# additional authority (each one's PoP key is auto-fetched from its own /pop),
# plus the operator label without which no path may include this relay.
# Built with array concatenation so the flags stay separate arguments.
$CommonArgs = @()
foreach ($u in $ExtraAuthUrls) { $CommonArgs += @("--extra-authority-url", $u) }
$CommonArgs += @("--operator", $Operator)

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
    ) + $CommonArgs
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
    ) + $CommonArgs
    $AdvMsg = "$($AdvIp):$Port"
}

# Token (only in closed/token mode) via a MACHINE env var so it is not visible
# in the task's command line. Open enrollment needs none.
if ($Token) { [Environment]::SetEnvironmentVariable("GOTHAM_ENROLL_TOKEN", $Token, "Machine") }

Write-Host "[4/6] Registering boot Scheduled Task (SYSTEM, background, auto-restart)..."
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

Write-Host "[5/6] Firewall + start now..."
# Rendezvous mode is OUTBOUND-only - no inbound port to open. Only open UDP when
# we advertise a directly-reachable address.
if ($Mode -eq "direct") {
    New-NetFirewallRule -DisplayName "Gotham QUIC relay (UDP $Port)" -Direction Inbound `
        -Protocol UDP -LocalPort $Port -Action Allow -ErrorAction SilentlyContinue | Out-Null
}
Start-ScheduledTask -TaskName "GothamRelay"

Write-Host "[6/6] Waiting for the authorities to accept enrollment..."
# Ask the AUTHORITIES, not the task state. A running task proves nothing: the
# directory is ground truth, and clients admit a relay only once k of n
# authorities have attested it (k=2 today). Being listed by the primary alone
# means the relay runs, looks healthy, and is dropped by every client.
$QuorumNeeded = if ($env:GOTHAM_QUORUM_NEEDED) { [int]$env:GOTHAM_QUORUM_NEEDED } else { 2 }
$AllAuthorities = @($AuthUrl) + $ExtraAuthUrls

function Get-AttestationCount {
    $n = 0
    foreach ($a in $AllAuthorities) {
        try {
            $body = (Invoke-WebRequest -Uri "$a/directory" -TimeoutSec 8 -UseBasicParsing).Content
            if ($body -match $PubKey) { $n++ }
        } catch { }
    }
    $n
}

$SeenBy = 0
for ($i = 0; $i -lt 20; $i++) {
    Start-Sleep -Seconds 5
    $SeenBy = Get-AttestationCount
    if ($SeenBy -ge $QuorumNeeded) { break }
}

Write-Host ""
Write-Host "============================================================"
if ($SeenBy -ge $QuorumNeeded) {
    Write-Host " Gotham relay is LIVE and ENROLLED ($SeenBy authorities attest it)"
} else {
    Write-Host " Gotham relay installed - NOT usable by clients yet" -ForegroundColor Yellow
    Write-Host " Attested by $SeenBy of the $QuorumNeeded authorities required."
    if ($SeenBy -gt 0) {
        Write-Host " It IS running and one authority sees it, but clients need a quorum,"
        Write-Host " so no traffic is routed through it until the others accept it."
    }
}
Write-Host " It starts automatically at every boot, in the background"
Write-Host " (Scheduled Task: GothamRelay)."
Write-Host " Public key : $PubKey"
Write-Host " Reachable  : $AdvMsg   (tier: $Tier, port $Port/udp)"
Write-Host " Authority  : $AuthUrl"
Write-Host " Also enrolled with: $($ExtraAuthUrls -join ' ')"
Write-Host " Operator   : $Operator   (a relay without a label is never routed)"
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
Write-Host " Re-check enrollment at any time (a relay can drop out later):" -ForegroundColor Cyan
Write-Host "   irm https://raw.githubusercontent.com/0x9Angel/gotham-relay/main/infra/scripts/diagnose-relay.ps1 | iex"
Write-Host "============================================================"
