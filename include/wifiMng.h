#ifndef _WIFI_MNG_H
#define _WIFI_MNG_H

#include "esp_wifi.h"

/**
 * @brief Init Wifi interface
 * 
 */
esp_err_t wifi_init(void);


/**
 * @brief Start wifi in AP mode
 * 
 */
void wifi_start_softap(void);


/**
 * @brief Start wifi AP with given settings
 * 
 * @param wifi_config 
 */
void wifi_ap_clone(wifi_config_t *wifi_config);

#endif