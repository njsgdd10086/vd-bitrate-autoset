@echo off
setlocal
set "VSDIR="
for /f "tokens=*" %%i in ('"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath') do set "VSDIR=%%i"
call "%VSDIR%\VC\Auxiliary\Build\vcvars64.bat" >nul
cl /nologo /O2 /Zi /EHsc /utf-8 main.cpp scanner.cpp /Fe:vd-bitrate-autoset_dbg.exe /link user32.lib gdi32.lib comctl32.lib advapi32.lib psapi.lib /SUBSYSTEM:WINDOWS
endlocal
