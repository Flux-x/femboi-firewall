@echo off
REM Femboi Firewall Windows cross-compilation script
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"

set "OUT=bin"
set "TARGET_BIN=%OUT%\femboi-firewall"
set "XDP_BIN=%OUT%\femboi-firewall-xdp"
set "OBJDIR=%OUT%\obj-linux"
set "ZIG_DIR=%CD%\tools\zig"
set "ZIG=%ZIG_DIR%\zig.exe"
set "ZIG_VERSION=0.13.0"
set "ARCH=x86_64"

set "DO_CLEAN=0"
set "DO_CHECK=0"
set "FORCE_ZIG=0"

:parse_args
if "%~1"=="" goto args_done
if /i "%~1"=="--clean"       ( set "DO_CLEAN=1" & shift & goto parse_args )
if /i "%~1"=="--check"       ( set "DO_CHECK=1" & shift & goto parse_args )
if /i "%~1"=="--install-zig" ( set "FORCE_ZIG=1" & shift & goto parse_args )
if /i "%~1"=="--target" (
    if /i "%~2"=="arm64"  ( set "ARCH=aarch64" & shift & shift & goto parse_args )
    if /i "%~2"=="aarch64" ( set "ARCH=aarch64" & shift & shift & goto parse_args )
    echo [!] Unknown target: %~2
    exit /b 2
)
if /i "%~1"=="-h" goto usage
if /i "%~1"=="--help" goto usage
echo [!] Unknown option: %~1
exit /b 2

:args_done

if "%DO_CLEAN%"=="1" (
    echo [*] Cleaning...
    if exist "%OBJDIR%" rmdir /s /q "%OBJDIR%"
    if exist "%TARGET_BIN%" del /q "%TARGET_BIN%"
    if exist "%XDP_BIN%" del /q "%XDP_BIN%"
    echo [+] Clean.
    if "%DO_CHECK%"=="0" goto :eof
)

if "%ARCH%"=="aarch64" (
    set "ZIG_TARGET=aarch64-linux-musl"
) else (
    set "ZIG_TARGET=x86_64-linux-musl"
)

echo ==========================================
echo  Femboi Firewall — Linux cross build
echo  target: %ZIG_TARGET%
echo ==========================================
echo.

set "SRC=linux\src\util.cpp linux\src\engine.cpp linux\src\nft.cpp linux\src\dpi.cpp linux\src\main.cpp"

for %%F in (%SRC%) do (
    if not exist "%%F" (
        echo [HATA] missing: %%F
        exit /b 1
    )
)

if "%FORCE_ZIG%"=="1" (
    if exist "%ZIG_DIR%" rmdir /s /q "%ZIG_DIR%"
    set "ZIG="
)

if not "%ZIG%"=="" if exist "%ZIG%" goto have_zig

where zig.exe >nul 2>&1
if not errorlevel 1 (
    for /f "delims=" %%Z in ('where zig.exe') do (
        set "ZIG=%%Z"
        goto have_zig
    )
)

echo [*] Downloading portable zig %ZIG_VERSION%...
if not exist "tools" mkdir "tools"

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ErrorActionPreference='Stop';" ^
  "$ver='%ZIG_VERSION%';" ^
  "$url='https://ziglang.org/download/' + $ver + '/zig-windows-x86_64-' + $ver + '.zip';" ^
  "$zip=Join-Path $env:TEMP ('zig-' + $ver + '.zip');" ^
  "Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing;" ^
  "$dest=Join-Path (Split-Path -Parent '%ZIG_DIR%') 'zig-extract';" ^
  "if (Test-Path $dest) { Remove-Item -Recurse -Force $dest };" ^
  "Expand-Archive -Path $zip -DestinationPath $dest -Force;" ^
  "$inner = Get-ChildItem $dest -Directory | Select-Object -First 1;" ^
  "if (Test-Path '%ZIG_DIR%') { Remove-Item -Recurse -Force '%ZIG_DIR%' };" ^
  "Move-Item $inner.FullName '%ZIG_DIR%';" ^
  "Remove-Item $zip -Force"

if not exist "%ZIG%" (
    echo [HATA] zig not found
    exit /b 1
)

:have_zig
echo [+] zig: %ZIG%

if not exist "%OUT%" mkdir "%OUT%"
if not exist "%OBJDIR%" mkdir "%OBJDIR%"

set "CFLAGS=-target %ZIG_TARGET% -O2 -std=c++17 -pthread -w -DNDEBUG -DZIG_CROSS"
set "CFLAGS=%CFLAGS% -Ilinux\include -Ilinux\src -Ilinux\xdp"

echo.
echo [*] Compiling sources...
set "OBJS="
set "FAILED=0"

for %%F in (%SRC%) do (
    set "NAME=%%~nF"
    echo     %%~nxF
    "%ZIG%" c++ %CFLAGS% -c "%%F" -o "%OBJDIR%\!NAME!.o"
    if errorlevel 1 goto build_failed
    set "OBJS=!OBJS! %OBJDIR%\!NAME!.o"
)

set "XDP_SRC=linux\xdp\xdpctl.cpp"
if not exist "%XDP_SRC%" (
    echo [HATA] missing: %XDP_SRC%
    exit /b 1
)
echo     xdpctl.cpp
"%ZIG%" c++ %CFLAGS% -c "%XDP_SRC%" -o "%OBJDIR%\xdpctl.o"
if errorlevel 1 goto build_failed

if "%DO_CHECK%"=="1" (
    echo [+] Syntax check passed
    exit /b 0
)

echo.
echo [*] Linking %TARGET_BIN%...
"%ZIG%" c++ -target %ZIG_TARGET% -static -pthread %OBJS% -o "%TARGET_BIN%"
if errorlevel 1 goto build_failed

echo [*] Linking %XDP_BIN%...
"%ZIG%" c++ -target %ZIG_TARGET% -static -pthread "%OBJDIR%\util.o" "%OBJDIR%\xdpctl.o" -o "%XDP_BIN%"
if errorlevel 1 goto build_failed

call :verify_elf "%TARGET_BIN%"
if errorlevel 1 goto build_failed
call :verify_elf "%XDP_BIN%"
if errorlevel 1 goto build_failed

if exist "geoip.dat" (
    if not exist "%OUT%\geoip.dat" copy /y "geoip.dat" "%OUT%\geoip.dat" >nul
)

for %%S in ("%TARGET_BIN%") do set "SIZE=%%~zS"
for %%S in ("%XDP_BIN%") do set "XSIZE=%%~zS"

echo.
echo ==========================================
echo  [BASARILI] %OUT%
echo ==========================================
echo   %TARGET_BIN%   : %SIZE% byte
echo   %XDP_BIN%       : %XSIZE% byte
echo.
pause
exit /b 0

:verify_elf
if not exist "%~1" exit /b 1
powershell -NoProfile -Command ^
  "$b=[System.IO.File]::ReadAllBytes('%~1');" ^
  "if ($b.Length -lt 4) { exit 1 };" ^
  "if ($b[0] -eq 0x7F -and $b[1] -eq 0x45 -and $b[2] -eq 0x4C -and $b[3] -eq 0x46) { exit 0 } else { exit 1 }"
exit /b %errorlevel%

:build_failed
echo.
echo [HATA] Derleme basarisiz.
pause
exit /b 1

:usage
echo Usage: derle.bat [--clean] [--check] [--install-zig] [--target arm64]
exit /b 0
