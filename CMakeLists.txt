cmake_minimum_required(VERSION 3.11.0)
set(EXCLUDE_COMPONENTS
    esp_https_server
    esp_https_ota
    esp_http_client
    esp_driver_cam
)

if(NOT $ENV{PIOENV} STREQUAL "cardputer")
    list(APPEND EXCLUDE_COMPONENTS esp_lcd)
endif()

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(WifiPhisher)