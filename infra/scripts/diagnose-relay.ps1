# diagnose-relay.ps1 — why won't my Gotham relay enroll?
#
# Runs the INSTALLED relay with the EXACT command the background Scheduled Task
# uses (so it reproduces reality, including --advertise-addr) in the foreground
# for ~20s, captures its output, and prints a plain-language verdict.
#
# Paste-safe one-liner (ELEVATED PowerShell — Run as Administrator):
#   irm https://raw.githubusercontent.com/0x9Angel/gotham-relay/main/infra/scripts/diagnose-relay.ps1 | iex

$ErrorActionPreference = "Continue"

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
          ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host "Run this in an ELEVATED PowerShell (Run as Administrator)." -ForegroundColor Yellow; return }

$dir = Join-Path $env:ProgramData "Gotham"
$bin = Join-Path $dir "gotham-relay.exe"
$out = Join-Path $dir "diagnose.out"
$err = Join-Path $dir "diagnose.err"
if (-not (Test-Path $bin)) { Write-Host "Relay not installed ($bin is missing). Run the installer first." -ForegroundColor Yellow; return }

# Reproduce EXACTLY what the background task runs (so --advertise-addr etc. match).
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
if ($text -match "enrolled|directory updated|announced|enroll ok|enrol.*success") {
    Write-Host "[OK] The relay reached the authority and ENROLLED — you're in the network." -ForegroundColor Green
}
elseif ($text -match "probe|liveness|not reachable|unreachable|proof.of.presence|rejected|timeout|4[0-9][0-9] ") {
    Write-Host "[FIX] Your enrollment reached the authority, but it could NOT reach you back on the advertised UDP port." -ForegroundColor Yellow
    Write-Host "      => On your router, FORWARD the UDP port shown in RELAY OUTPUT to THIS PC's LAN IP, then wait ~1 min."
    Write-Host "      (If you're on a mobile hotspot / 4G-5G / shared connection, that's CGNAT — you cannot host a relay this way.)"
}
elseif ($text -match "UPnP|IGD") {
    Write-Host "[FIX] UPnP failure — reinstall (the latest installer auto-detects your public IP), or set GOTHAM_ADVERTISE_IP." -ForegroundColor Yellow
}
elseif ($text -match "bind|in use|10048|10013|os error 100") {
    Write-Host "[FIX] Cannot bind the UDP port (in use or blocked). Reinstall with GOTHAM_PORT=9101." -ForegroundColor Yellow
}
elseif ($text -match "connect|refused|dns|resolve|failed to reach") {
    Write-Host "[?] The relay could not reach the authority. Check outbound internet / the authority URL." -ForegroundColor Yellow
}
else {
    Write-Host "[?] Could not auto-classify — copy the RELAY OUTPUT above and send it to the operator." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Restarting the background task..."
Start-ScheduledTask -TaskName GothamRelay -ErrorAction SilentlyContinue | Out-Null
