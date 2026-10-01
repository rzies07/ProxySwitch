@echo off
setlocal
echo ----------------------------------------
echo PROXY SWITCH - BUILD
echo ----------------------------------------
set "CSC=%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%CSC%" set "CSC=%SystemRoot%\Microsoft.NET\Framework\v4.0.30319\csc.exe"
if not exist "%CSC%" (
    echo [ERROR] csc.exe not found.
    pause
    exit /b
)
"%CSC%" /nologo /target:winexe /win32icon:app.ico /out:ProxySwitch.exe ProxySwitch.cs
if %errorlevel% equ 0 (
    echo [SUCCESS] Build completed! Starting ProxySwitch.exe...
    start ProxySwitch.exe
) else (
    echo [ERROR] Compilation failed.
    pause
)
