$ErrorActionPreference = "Continue"

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
          ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host "Run this in an ELEVATED PowerShell (Run as Administrator)." -ForegroundColor Yellow; return }

$dir = Join-Path $env:ProgramData "Gotham"
$bin = Join-Path $dir "gotham-relay.exe"
$out = Join-Path $dir "diagnose.out"
$err = Join-Path $dir "diagnose.err"
if (-not (Test-Path $bin)) { Write-Host "Relay not installed ($bin is missing). Run the installer first." -ForegroundColor Yellow; return }

$task = Get-ScheduledTask -TaskName GothamRelay -ErrorAction SilentlyContinue
if ($task -and $task.Actions[0].Execute) {
    $exe    = $task.Actions[0].Execute
    $argStr = $task.Actions[0].Arguments
} else {
    $key    = Join-Path $dir "relay.key"
    $exe    = $bin
    $argStr = "run --key-file `"$key`" --listen-host 0.0.0.0 --listen-port 443 --authority-url http://144.24.205.188:8443 --tier mix --heartbeat-secs 60"
}

Write-Host "Stopping the background task, then running the relay ~20s to capture its output..."
Write-Host "Command: $exe $argStr" -ForegroundColor DarkGray
Stop-ScheduledTask -TaskName GothamRelay -ErrorAction SilentlyContinue | Out-Null
Start-Sleep -Seconds 1

Remove-Item $out, $err -ErrorAction SilentlyContinue
$p = Start-Process -FilePath $exe -ArgumentList $argStr -NoNewWindow -PassThru `
        -RedirectStandardOutput $out -RedirectStandardError $err
Start-Sleep -Seconds 20
if (-not $p.HasExited) { $p.Kill(); $exit = "(still running after 20s — normal if it enrolled; stopped it)" }
else { $exit = "(the relay EXITED on its own with code $($p.ExitCode) — it crashed)" }

$text = ((Get-Content $out -Raw -ErrorAction SilentlyContinue) + "`n" +
         (Get-Content $err -Raw -ErrorAction SilentlyContinue)).Trim()

Write-Host ""
Write-Host "===== RELAY OUTPUT =====" -ForegroundColor Cyan
if ($text) { Write-Host $text } else { Write-Host "(no output captured)" }
Write-Host "$exit"
Write-Host "===== VERDICT =====" -ForegroundColor Cyan
$pubkey = if ($text -match "identity public key: ([0-9a-f]{64})") { $Matches[1] } else { $null }
$viaRendezvous = $argStr -match "--rendezvous-key"
$auths = @([regex]::Matches($argStr, '--(?:extra-)?authority-url\s+(\S+)') | ForEach-Object { $_.Groups[1].Value })
$listed = 0
if ($pubkey) {
    foreach ($a in $auths) {
        try {
            $body = (Invoke-WebRequest -Uri "$a/directory" -TimeoutSec 8 -UseBasicParsing).Content
            if ($body -match $pubkey) { $listed++ }
        } catch { }
    }
}
if ($text -match "error: (unexpected argument|invalid value|a value is required)") {
    Write-Host "[FIX] The relay rejected its own settings and stopped. Re-run the latest installer: it rewrites the task." -ForegroundColor Yellow
}
elseif ($text -match "enrolled with directory authority") {
    if ($listed -ge 2) {
        Write-Host "[OK] Enrolled and published by $listed authorities: clients can route through this relay." -ForegroundColor Green
    } else {
        Write-Host "[INFO] Enrolled, but published by only $listed of $($auths.Count) authorities." -ForegroundColor Yellow
        Write-Host "      Each operator can have at most 5 published relays, and each network 3 per /24 and 8 per /16."
        Write-Host "      If your operator name already has 5 relays, this one is accepted but stays unpublished."
        Write-Host "      If the installer said 0 authorities while this test enrolls, the background task lacks the"
        Write-Host "      enrollment token: re-run the latest installer with `$env:GOTHAM_ENROLL_TOKEN set."
    }
}
elseif ($text -match "missing or invalid enroll token") {
    Write-Host "[FIX] The authorities refused the enrollment token. Ask the network operator for it, then re-run" -ForegroundColor Yellow
    Write-Host "      the installer with `$env:GOTHAM_ENROLL_TOKEN set."
}
elseif ($text -match "rendezvous liveness query failed|rendezvous relay does not host|rendezvous relay not found" -or
        ($viaRendezvous -and $text -match "enroll rejected")) {
    Write-Host "[SERVER] The rendezvous point did not confirm this relay to the authorities. This is on the network" -ForegroundColor Yellow
    Write-Host "      side, not yours. Until the operator updates the rendezvous relays, use direct mode: forward a UDP"
    Write-Host "      port on your router to this PC, then re-run the installer with `$env:GOTHAM_RENDEZVOUS='off'."
}
elseif ($text -match "liveness/proof-of-possession probe failed|not reachable|unreachable|timed out") {
    Write-Host "[FIX] The authorities could not reach this relay on its advertised UDP port." -ForegroundColor Yellow
    Write-Host "      => On your router, FORWARD that UDP port to THIS PC's LAN IP, then wait ~1 min."
    Write-Host "      Some boxes only allow ports above 32768: pick one, forward it, re-run with `$env:GOTHAM_PORT."
    Write-Host "      Behind a mobile hotspot / 4G-5G / CGNAT, no port can be forwarded: that connection cannot host a relay."
}
elseif ($text -match "UPnP|IGD") {
    Write-Host "[FIX] UPnP failure: reinstall (the installer detects your public IP), or set GOTHAM_ADVERTISE_IP." -ForegroundColor Yellow
}
elseif ($text -match "bind|in use|10048|10013|os error 100") {
    Write-Host "[FIX] Cannot bind the UDP port (in use or blocked). Reinstall with another GOTHAM_PORT." -ForegroundColor Yellow
}
elseif ($text -match "connect|refused|dns|resolve|failed to reach") {
    Write-Host "[?] The relay could not reach the authority. Check outbound internet / the authority URL." -ForegroundColor Yellow
}
else {
    Write-Host "[?] Could not auto-classify: copy the RELAY OUTPUT above and send it to the operator." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Restarting the background task..."
Start-ScheduledTask -TaskName GothamRelay -ErrorAction SilentlyContinue | Out-Null
