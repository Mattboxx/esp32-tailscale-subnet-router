@echo off
setlocal
cd /d "%~dp0"
title Installazione pulita ESP32-S3 - cancella configurazione
echo.
echo ATTENZIONE: QUESTA PROCEDURA CANCELLA TUTTE LE IMPOSTAZIONI.
echo WiFi, password, Tailscale, MQTT e dispositivi WOL andranno persi.
echo.
set /p "OK=Scrivi SI e premi Invio per continuare: "
if /I not "%OK%"=="SI" goto :annulla
set "PORT_ARGS="
if not "%~1"=="" set "PORT_ARGS=--port %~1"
esptool.exe --chip esp32s3 %PORT_ARGS% erase-flash
if errorlevel 1 goto :errore
esptool.exe --chip esp32s3 %PORT_ARGS% --baud 460800 write-flash 0x0 firmware-factory.bin
if errorlevel 1 goto :errore
echo.
echo ========================================
echo FLASH COMPLETATO. La scheda si riavvia.
echo Collegati al suo AP e apri http://192.168.4.1/
echo ========================================
pause
exit /b 0
:annulla
echo Operazione annullata.
pause
exit /b 2
:errore
echo.
echo FLASH NON RIUSCITO.
echo Controlla cavo e porta COM. Se serve usa BOOT/RESET come da README.txt.
pause
exit /b 1
