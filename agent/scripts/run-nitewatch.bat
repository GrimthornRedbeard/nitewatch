@echo off
rem NiteWatch launcher — self-elevates (ETW needs Administrator), then serves the
rem dashboard. Double-click this instead of the .exe.

net session >nul 2>&1
if %errorlevel% neq 0 (
  echo Requesting administrator privileges...
  powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

cd /d "%~dp0"
echo Starting NiteWatch... the dashboard will open at http://127.0.0.1:8973
nitewatch.exe --serve
echo.
echo NiteWatch stopped. Press any key to close.
pause >nul
