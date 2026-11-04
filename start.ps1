# BugBîner AI — PowerShell Start Script
# Starts the server as a completely independent background process (survives terminal close)

$ROOT   = $PSScriptRoot
$PYTHON = "$ROOT\.venv\Scripts\python.exe"
$MAIN   = "$ROOT\backend\main.py"
$LOG    = "$ROOT\server.log"
$PORT   = 9090

Write-Host ""
Write-Host "  BugBîner AI  v1.0" -ForegroundColor Cyan
Write-Host "  Gen AI-Powered Vulnerability Scanner" -ForegroundColor Cyan
Write-Host ""

# Kill any existing server on the port
$existing = (netstat -ano 2>$null | Select-String ":$PORT\s.*LISTEN" |
    ForEach-Object { ($_ -split "\s+")[-1] } | Select-Object -First 1)
if ($existing) {
    Write-Host "  [*] Stopping old server (PID $existing)..." -ForegroundColor Yellow
    taskkill /F /PID $existing /T >$null 2>&1
    Start-Sleep 1
}

# Ensure reports folder exists
New-Item -ItemType Directory -Path "$ROOT\reports" -Force >$null

# Launch server as a DETACHED independent process that survives terminal close
# Uses cmd /c to redirect output to log and run truly detached
Write-Host "  [*] Starting server in background..." -ForegroundColor Green

$proc = Start-Process `
    -FilePath "cmd.exe" `
    -ArgumentList "/c `"`"$PYTHON`" `"$MAIN`" > `"$LOG`" 2>&1`"" `
    -WorkingDirectory "$ROOT\backend" `
    -WindowStyle Hidden `
    -PassThru

# Wait a moment then verify port is listening
Start-Sleep 2
$listening = netstat -ano 2>$null | Select-String ":$PORT\s.*LISTEN"
if ($listening) {
    Write-Host "  [OK] Server running  PID=$($proc.Id)  -> http://localhost:$PORT" -ForegroundColor Green
    Write-Host "  [*] Logs -> $LOG" -ForegroundColor Gray
    Write-Host "  [*] To stop: taskkill /F /PID $($proc.Id) /T" -ForegroundColor Gray
    Write-Host ""
    Start-Process "http://localhost:$PORT"
} else {
    Write-Host "  [!] Server may not be listening yet. Check: $LOG" -ForegroundColor Yellow
    Write-Host ""
}
