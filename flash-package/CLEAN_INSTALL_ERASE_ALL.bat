@echo off
setlocal
cd /d "%~dp0"
title ESP32-S3 clean install - erase settings
echo.
echo WARNING: THIS ERASES EVERY SAVED SETTING.
echo WiFi, passwords, Tailscale, MQTT, ntfy and WOL devices will be lost.
echo.
set /p "OK=Type YES and press Enter to continue: "
if /I not "%OK%"=="YES" goto :cancel
set "PORT_ARGS="
if not "%~1"=="" set "PORT_ARGS=--port %~1"
esptool.exe --chip esp32s3 %PORT_ARGS% erase-flash
if errorlevel 1 goto :error
esptool.exe --chip esp32s3 %PORT_ARGS% --baud 460800 write-flash 0x0 firmware-factory.bin
if errorlevel 1 goto :error
echo.
echo ========================================
echo FLASH COMPLETE. The board is restarting.
echo Join its access point and open http://192.168.4.1/
echo ========================================
pause
exit /b 0
:cancel
echo Operation cancelled.
pause
exit /b 2
:error
echo.
echo FLASH FAILED.
echo Check the cable and COM port. If needed, use BOOT/RESET as described in README.txt.
pause
exit /b 1
