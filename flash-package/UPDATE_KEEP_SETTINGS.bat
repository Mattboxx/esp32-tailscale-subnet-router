@echo off
setlocal
cd /d "%~dp0"
title ESP32-S3 update - keep settings
set "PORT_ARGS="
if not "%~1"=="" set "PORT_ARGS=--port %~1"
echo.
echo ESP32-S3 ROUTER - UPDATE
echo Saved settings will be preserved.
echo Close every serial monitor first.
echo.
pause
esptool.exe --chip esp32s3 %PORT_ARGS% --baud 460800 write-flash --flash-mode dio --flash-freq 80m --flash-size 4MB 0x0 bootloader.bin 0x8000 partitions.bin 0x19000 ota_data_initial.bin 0x20000 firmware.bin
if errorlevel 1 goto :error
echo.
echo ========================================
echo FLASH COMPLETE. The board is restarting.
echo ========================================
pause
exit /b 0
:error
echo.
echo FLASH FAILED.
echo Check the cable and COM port. If needed, use BOOT/RESET as described in README.txt.
pause
exit /b 1
