@echo off
setlocal
cd /d "%~dp0"
title Aggiornamento ESP32-S3 - mantiene configurazione
set "PORT_ARGS="
if not "%~1"=="" set "PORT_ARGS=--port %~1"
echo.
echo ESP32-S3 ROUTER - AGGIORNAMENTO
echo Le impostazioni salvate verranno mantenute.
echo Chiudi prima qualsiasi monitor seriale.
echo.
pause
esptool.exe --chip esp32s3 %PORT_ARGS% --baud 460800 write-flash --flash-mode dio --flash-freq 80m --flash-size 4MB 0x0 bootloader.bin 0x8000 partitions.bin 0x19000 ota_data_initial.bin 0x20000 firmware.bin
if errorlevel 1 goto :errore
echo.
echo ========================================
echo FLASH COMPLETATO. La scheda si riavvia.
echo ========================================
pause
exit /b 0
:errore
echo.
echo FLASH NON RIUSCITO.
echo Controlla cavo e porta COM. Se serve usa BOOT/RESET come da README.txt.
pause
exit /b 1
