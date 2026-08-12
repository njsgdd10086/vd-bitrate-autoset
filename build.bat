@echo off
setlocal enabledelayedexpansion

set "VSDIR="
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist "%VSWHERE%" (
    for /f "tokens=*" %%i in ('"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath') do set "VSDIR=%%i"
)

if not defined VSDIR (
    echo [ERROR] Visual Studio C++ tools not found. Install "Desktop development with C++" workload.
    exit /b 1
)

for /d %%i in ("%VSDIR%\VC\Tools\MSVC\*") do set "MSVCVER=%%i"
if not defined MSVCVER (
    echo [ERROR] MSVC toolset not found under %VSDIR%\VC\Tools\MSVC
    exit /b 1
)

call "%VSDIR%\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 (
    echo [ERROR] vcvars64.bat failed.
    exit /b 1
)

cl /nologo /O2 /EHsc /utf-8 main.cpp scanner.cpp /Fe:vd-bitrate-autoset.exe /link user32.lib gdi32.lib comctl32.lib advapi32.lib psapi.lib /SUBSYSTEM:WINDOWS
if exist vd-bitrate-autoset.exe (
    echo.
    echo Build OK: vd-bitrate-autoset.exe
)
endlocal
