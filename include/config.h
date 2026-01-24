#ifndef _CONFIG_H
#define _CONFIG_H

#include <esp_system.h>
#include <esp_wifi.h>

/* WIFI CONFIGURATION */
#define DEFAULT_WIFI_SSID           "MagicWifi"
#define DEFAULT_WIFI_PASS           "MagicWifi1234"
#define DEFAULT_WIFI_MAX_CONN       5
#define DEFAULT_WIFI_CHAN           1
#define DEFAULT_WIFI_AUTH           WIFI_AUTH_WPA_WPA2_PSK


/**
 * @brief Save string value to flash
 * 
 * @param key 
 * @param value 
 */
void save_string_to_flash(const char* key, const char* value);


/**
 * @brief Read string value from flash
 * 
 * @param key 
 */
esp_err_t read_string_from_flash(const char* key, char* value);


/**
 * @brief Save int32 to flash
 * 
 * @param key 
 * @param value 
 */
void save_int_to_flash(const char* key, int32_t value);


/**
 * @brief Read int32_ from Flash
 * 
 * @param key 
 * @param value 
 * @return esp_err_t 
 */
esp_err_t read_int_from_flash(const char* key, int32_t *value);


#endif