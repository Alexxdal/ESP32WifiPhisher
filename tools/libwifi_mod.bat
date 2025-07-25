@echo off

echo Mod libnet80211 for ESP32S3
copy %userprofile%\.platformio\packages\framework-espidf\components\esp_wifi\lib\esp32s3\libnet80211.a %userprofile%\.platformio\packages\framework-espidf\components\esp_wifi\lib\esp32s3\libnet80211.a.old
%userprofile%\.platformio\packages\toolchain-xtensa-esp-elf\bin\xtensa-esp32s3-elf-objcopy.exe --weaken-symbol=ieee80211_raw_frame_sanity_check %userprofile%\.platformio\packages\framework-espidf\components\esp_wifi\lib\esp32s3\libnet80211.a.old %userprofile%\.platformio\packages\framework-espidf\components\esp_wifi\lib\esp32s3\libnet80211.a

echo Mod libnet80211 for ESP32S2
copy %userprofile%\.platformio\packages\framework-espidf\components\esp_wifi\lib\esp32s2\libnet80211.a %userprofile%\.platformio\packages\framework-espidf\components\esp_wifi\lib\esp32s2\libnet80211.a.old
%userprofile%\.platformio\packages\toolchain-xtensa-esp-elf\bin\xtensa-esp32s2-elf-objcopy.exe --weaken-symbol=ieee80211_raw_frame_sanity_check %userprofile%\.platformio\packages\framework-espidf\components\esp_wifi\lib\esp32s2\libnet80211.a.old %userprofile%\.platformio\packages\framework-espidf\components\esp_wifi\lib\esp32s2\libnet80211.a

echo Mod libnet80211 for ESP32
copy %userprofile%\.platformio\packages\framework-espidf\components\esp_wifi\lib\esp32\libnet80211.a %userprofile%\.platformio\packages\framework-espidf\components\esp_wifi\lib\esp32\libnet80211.a.old
%userprofile%\.platformio\packages\toolchain-xtensa-esp-elf\bin\xtensa-esp32-elf-objcopy.exe --weaken-symbol=ieee80211_raw_frame_sanity_check %userprofile%\.platformio\packages\framework-espidf\components\esp_wifi\lib\esp32\libnet80211.a.old %userprofile%\.platformio\packages\framework-espidf\components\esp_wifi\lib\esp32\libnet80211.a

echo Mod libnet80211 for ESP32C6
copy %userprofile%\.platformio\packages\framework-espidf\components\esp_wifi\lib\esp32c6\libnet80211.a %userprofile%\.platformio\packages\framework-espidf\components\esp_wifi\lib\esp32c6\libnet80211.a.old
%userprofile%\.platformio\packages\toolchain-riscv32-esp\bin\riscv32-esp-elf-objcopy.exe --weaken-symbol=ieee80211_raw_frame_sanity_check %userprofile%\.platformio\packages\framework-espidf\components\esp_wifi\lib\esp32c6\libnet80211.a.old %userprofile%\.platformio\packages\framework-espidf\components\esp_wifi\lib\esp32c6\libnet80211.a

echo Mod libnet80211 for ESP32C5
copy %userprofile%\.platformio\packages\framework-espidf\components\esp_wifi\lib\esp32c5\libnet80211.a %userprofile%\.platformio\packages\framework-espidf\components\esp_wifi\lib\esp32c5\libnet80211.a.old
%userprofile%\.platformio\packages\toolchain-riscv32-esp\bin\riscv32-esp-elf-objcopy.exe --weaken-symbol=ieee80211_raw_frame_sanity_check %userprofile%\.platformio\packages\framework-espidf\components\esp_wifi\lib\esp32c5\libnet80211.a.old %userprofile%\.platformio\packages\framework-espidf\components\esp_wifi\lib\esp32c5\libnet80211.a

echo Mod libnet80211 for ESP32C3
copy %userprofile%\.platformio\packages\framework-espidf\components\esp_wifi\lib\esp32c3\libnet80211.a %userprofile%\.platformio\packages\framework-espidf\components\esp_wifi\lib\esp32c3\libnet80211.a.old
%userprofile%\.platformio\packages\toolchain-riscv32-esp\bin\riscv32-esp-elf-objcopy.exe --weaken-symbol=ieee80211_raw_frame_sanity_check %userprofile%\.platformio\packages\framework-espidf\components\esp_wifi\lib\esp32c3\libnet80211.a.old %userprofile%\.platformio\packages\framework-espidf\components\esp_wifi\lib\esp32c3\libnet80211.a