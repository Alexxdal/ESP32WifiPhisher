#ifndef _WIFI_MNG_H
#define _WIFI_MNG_H

#include <esp_err.h>
#include <esp_wifi.h>


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
 * @param bssid 
 */
void wifi_ap_clone(wifi_config_t *wifi_config, uint8_t *bssid);


/**
 * @brief Safely set wifi channel, deauth connected stations if needed
 * 
 * @param new_channel 
 * @return esp_err_t 
 */
esp_err_t wifi_set_channel_safe(uint8_t new_channel);


/**
 * @brief Send ROC request to set a channel temporarly
 * @param window default 150ms, its the time window for the attack in this channel
 */
esp_err_t wifi_set_temporary_channel(uint8_t new_channel, uint32_t window);


#endif