@echo off
title BugBiner AI - Gen AI-Powered Vulnerability Scanner
cd /d %~dp0
setlocal enabledelayedexpansion

echo.
echo  +===================================+
echo  ^|       BugBiner AI  v1.0           ^|
echo  ^|   Gen AI-Powered Vuln Scanner      ^|
echo  ^|   Built by Joudi Janble           ^|
echo  +===================================+
echo.
echo  [*] Checking everything is installed before launch...
echo.

REM ============================================================
REM  1) Python + virtual environment
REM ============================================================
where python >nul 2>&1
if not errorlevel 1 goto py_ok
echo  [*] Python not found - installing via winget...
winget install -e --id Python.Python.3.12 --silent --accept-package-agreements --accept-source-agreements
where python >nul 2>&1
if not errorlevel 1 goto py_ok
echo  [!] Python was installed but is not on PATH yet. Close this window and run start.bat again.
pause & exit /b 1
:py_ok
if not exist ".venv" (
    echo  [*] Creating Python virtual environment...
    python -m venv .venv
    if errorlevel 1 ( echo  [!] Failed to create the virtual environment. & pause & exit /b 1 )
)

REM ============================================================
REM  2) Python dependencies
REM ============================================================
echo  [*] Checking Python dependencies...
.venv\Scripts\python -c "import fastapi, uvicorn, aiohttp, requests" >nul 2>&1
if not errorlevel 1 (
    echo  [OK] Python dependencies already installed.
) else (
    echo  [*] Installing Python dependencies ^(downloading, please wait^)...
    .venv\Scripts\python -m pip install --upgrade pip --disable-pip-version-check
    .venv\Scripts\python -m pip install -r requirements.txt --prefer-binary --disable-pip-version-check
    if errorlevel 1 ( echo  [!] pip install failed. & pause & exit /b 1 )
)

REM ============================================================
REM  3) Node.js + crawler dependencies (puppeteer browser)
REM ============================================================
where node >nul 2>&1
if not errorlevel 1 goto node_ok
echo  [*] Node.js not found - installing via winget...
winget install -e --id OpenJS.NodeJS.LTS --silent --accept-package-agreements --accept-source-agreements
where node >nul 2>&1
if not errorlevel 1 goto node_ok
echo  [!] Node.js was installed but is not on PATH yet. Close this window and run start.bat again.
pause & exit /b 1
:node_ok
if not exist "backend\node_modules\puppeteer" (
    echo  [*] Installing crawler dependencies ^(downloads a headless browser, may take a few minutes^)...
    pushd backend
    call npm install
    popd
)
if not exist "backend\node_modules\puppeteer" ( echo  [!] npm install failed. & pause & exit /b 1 )
echo  [OK] Crawler dependencies ready.

REM ============================================================
REM  4) Ollama (the local model runner) - install if missing
REM ============================================================
set "OLLAMA="
where ollama >nul 2>&1 && set "OLLAMA=ollama"
if not defined OLLAMA if exist "%LOCALAPPDATA%\Programs\Ollama\ollama.exe" set "OLLAMA=%LOCALAPPDATA%\Programs\Ollama\ollama.exe"
if defined OLLAMA goto ollama_found

echo  [*] Ollama not found - installing automatically...
winget install -e --id Ollama.Ollama --silent --accept-package-agreements --accept-source-agreements
where ollama >nul 2>&1 && set "OLLAMA=ollama"
if not defined OLLAMA if exist "%LOCALAPPDATA%\Programs\Ollama\ollama.exe" set "OLLAMA=%LOCALAPPDATA%\Programs\Ollama\ollama.exe"
if defined OLLAMA goto ollama_found

echo  [*] winget unavailable - downloading the Ollama installer...
powershell -NoProfile -Command "Invoke-WebRequest -Uri https://ollama.com/download/OllamaSetup.exe -OutFile '%TEMP%\OllamaSetup.exe'"
if exist "%TEMP%\OllamaSetup.exe" (
    echo  [*] Running the Ollama installer ^(silent^)...
    start /wait "" "%TEMP%\OllamaSetup.exe" /VERYSILENT /SUPPRESSMSGBOXES
)
if not defined OLLAMA if exist "%LOCALAPPDATA%\Programs\Ollama\ollama.exe" set "OLLAMA=%LOCALAPPDATA%\Programs\Ollama\ollama.exe"
where ollama >nul 2>&1 && set "OLLAMA=ollama"
if defined OLLAMA goto ollama_found

echo  [!] Could not install Ollama. Install it from https://ollama.com and re-run.
pause & exit /b 1
:ollama_found
echo  [OK] Ollama found: %OLLAMA%

REM ============================================================
REM  5) Parallel-channel settings (chat + scan run together)
REM ============================================================
echo  [*] Configuring parallel channels ^(so chat keeps working during a scan^)...
setx OLLAMA_NUM_PARALLEL 3 >nul
setx SCAN_LLM_PARALLEL 2 >nul
setx OLLAMA_MAX_LOADED_MODELS 2 >nul
setx OLLAMA_KEEP_ALIVE 30m >nul
set "OLLAMA_NUM_PARALLEL=3"
set "SCAN_LLM_PARALLEL=2"
set "OLLAMA_MAX_LOADED_MODELS=2"
set "OLLAMA_KEEP_ALIVE=30m"

REM ============================================================
REM  6) Make sure the Ollama server is running
REM ============================================================
curl -s -o nul http://localhost:11434/api/version
if not errorlevel 1 goto ollama_up
echo  [*] Starting the Ollama server...
start "" /b cmd /c ""%OLLAMA%" serve > "%~dp0ollama.log" 2>&1"
set /a _w=0
:waitollama
timeout /t 1 /nobreak >nul
curl -s -o nul http://localhost:11434/api/version
if not errorlevel 1 goto ollama_up
set /a _w+=1
if !_w! lss 25 goto waitollama
echo  [!] The Ollama server did not start. Check ollama.log
pause & exit /b 1
:ollama_up
echo  [OK] Ollama server is up.

REM ============================================================
REM  7) The model (qwen2.5:7b) - download if missing
REM ============================================================
echo  [*] Checking model qwen2.5:7b...
"%OLLAMA%" list 2>nul | findstr /i /c:"qwen2.5:7b" >nul
if not errorlevel 1 goto model_ok
echo  [*] Downloading model qwen2.5:7b ^(~5 GB - progress shown below^)...
"%OLLAMA%" pull qwen2.5:7b
if errorlevel 1 ( echo  [!] Model download failed. & pause & exit /b 1 )
:model_ok
echo  [OK] Model qwen2.5:7b ready.

REM ============================================================
REM  8) Launch the server + open the interface
REM ============================================================
if not exist "reports" mkdir reports

echo  [*] Stopping any old server on port 9090...
for /f "tokens=5" %%a in ('netstat -ano 2^>nul ^| findstr :9090 ^| findstr LISTENING') do taskkill /PID %%a /F >nul 2>&1

echo  [*] Starting the server on http://localhost:9090 ...
cd backend
start "" /b cmd /c "..\.venv\Scripts\python main.py > ..\server.log 2>&1"
cd ..

set /a _s=0
:waitserver
timeout /t 1 /nobreak >nul
curl -s -o nul http://localhost:9090/
if not errorlevel 1 goto serverup
set /a _s+=1
if !_s! lss 25 goto waitserver
:serverup
start http://localhost:9090

echo.
echo  [OK] Everything is ready  -^>  http://localhost:9090
echo  [*] Server log: server.log    Ollama log: ollama.log
echo.
pause
