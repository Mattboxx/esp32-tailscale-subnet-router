ESP32-S3 ROUTER - PACCHETTO FLASH WINDOWS
========================================

Requisiti: Windows 10/11 a 64 bit, ESP32-S3 collegata via USB e nessun
monitor seriale aperto.

AGGIORNAMENTO SENZA PERDERE LE IMPOSTAZIONI
1. Doppio clic su AGGIORNA_SENZA_CANCELLARE.bat.
2. Attendi FLASH COMPLETATO.
3. Se il rilevamento automatico non riesce, apri il Prompt dei comandi nella
   cartella e indica la porta, per esempio:
     AGGIORNA_SENZA_CANCELLARE.bat COM6

INSTALLAZIONE PULITA / RECUPERO
1. Doppio clic su FLASH_PULITO_CANCELLA_TUTTO.bat.
2. Conferma scrivendo SI.
3. Questa procedura CANCELLA WiFi, password, chiavi Tailscale, MQTT, WOL e ogni
   altra impostazione. Poi collegati all'AP della ESP e apri 192.168.4.1.

Se compare Failed to connect: tieni premuto BOOT, premi e rilascia RESET,
rilascia BOOT quando il programma tenta il collegamento e riprova.

Contenuto:
- firmware-factory.bin: immagine unica per installazione pulita
- bootloader.bin, partitions.bin, ota_data_initial.bin e firmware.bin:
  immagini usate dall'aggiornamento che preserva la configurazione NVS
- esptool.exe: tool ufficiale Espressif; versione in VERSIONI.txt

Comandi manuali per installazione pulita (cambia COM6 se necessario):
  esptool.exe --chip esp32s3 --port COM6 erase-flash
  esptool.exe --chip esp32s3 --port COM6 --baud 460800 write-flash 0x0 firmware-factory.bin
