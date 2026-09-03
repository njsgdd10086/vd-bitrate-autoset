@echo off
setlocal
set "VSDIR="
for /f "tokens=*" %%i in ('"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath') do set "VSDIR=%%i"
if not defined VSDIR (
    echo [ERROR] Visual Studio C++ tools not found. Install "Desktop development with C++" workload.
    exit /b 1
)
call "%VSDIR%\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 (
    echo [ERROR] vcvars64.bat failed.
    exit /b 1
)
cl /nologo /Od /MTd /W4 /permissive- /EHsc /utf-8 /Zi /RTC1 main.cpp scanner.cpp /Fe:vd-bitrate-autoset_dbg.exe /link user32.lib gdi32.lib comctl32.lib advapi32.lib psapi.lib /SUBSYSTEM:WINDOWS /DEBUG
if errorlevel 1 (
    echo [ERROR] Debug build failed.
    exit /b 1
)
if not exist vd-bitrate-autoset_dbg.exe (
    echo [ERROR] Debug executable was not produced.
    exit /b 1
)
echo.
echo Debug build OK: vd-bitrate-autoset_dbg.exe
endlocal
