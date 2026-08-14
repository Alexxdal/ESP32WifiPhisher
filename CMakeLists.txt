cmake_minimum_required(VERSION 3.11.0)
set(EXCLUDE_COMPONENTS
    # HTTPS server / OTA / HTTP client - il progetto usa solo esp_http_server
    # in chiaro (WebSocket + REST per l'admin panel), niente OTA via rete.
    esp_https_server
    esp_https_ota
    esp_http_client
    # Driver LCD/camera - nessun display o fotocamera nel progetto. Questo e'
    # anche il componente il cui file rgb/esp_lcd_panel_rgb.c mandava in crash
    # GCC con "internal compiler error" sull'env cardputer: escludendolo,
    # quel file non viene proprio piu' compilato.
    esp_lcd
    esp_driver_cam
)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(WifiPhisher)
