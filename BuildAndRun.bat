@echo off
setlocal
echo ----------------------------------------
echo PROXY DOMINATOR - CLEAN SOLID BUILD
echo ----------------------------------------

set "CSC=%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%CSC%" set "CSC=%SystemRoot%\Microsoft.NET\Framework\v4.0.30319\csc.exe"
if not exist "%CSC%" (
    echo [ERROR] csc.exe compiler not found.
    pause
    exit /b
)

echo [1] Compiling ProxyDominator.exe with app.ico...
"%CSC%" /nologo /target:winexe /win32icon:app.ico /out:ProxyDominator.exe ProxyDominator.cs

if %errorlevel% equ 0 (
    echo [2] Success! Starting app...
    start ProxyDominator.exe
) else (
    echo [ERROR] Compilation failed.
    pause
)
