ESP32-S3 ROUTER - WINDOWS FLASH PACKAGE
=======================================

Firmware: 0.1.20-Mattboxx

Requirements: 64-bit Windows 10/11, an ESP32-S3 connected over USB, and
every serial monitor closed.

UPDATE WITHOUT LOSING SETTINGS
1. Double-click UPDATE_KEEP_SETTINGS.bat.
2. Wait for FLASH COMPLETE.
3. If automatic port detection fails, open Command Prompt in this folder and
   provide the port, for example:
     UPDATE_KEEP_SETTINGS.bat COM6

CLEAN INSTALL / RECOVERY
1. Double-click CLEAN_INSTALL_ERASE_ALL.bat.
2. Confirm by typing YES.
3. This ERASES WiFi, passwords, Tailscale keys, MQTT, ntfy, WOL and every
   other setting. Then join the ESP access point and open 192.168.4.1.

If "Failed to connect" appears: hold BOOT, press and release RESET, then
release BOOT when the program attempts to connect and retry.

Contents:
- firmware-factory.bin: single image for a clean installation
- bootloader.bin, partitions.bin, ota_data_initial.bin and firmware.bin:
  images used by the update that preserves the NVS configuration
- esptool.exe: official Espressif tool; see VERSIONS.txt

Manual clean-install commands (change COM6 if needed):
  esptool.exe --chip esp32s3 --port COM6 erase-flash
  esptool.exe --chip esp32s3 --port COM6 --baud 460800 write-flash 0x0 firmware-factory.bin
