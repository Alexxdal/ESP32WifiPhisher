#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_mac.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "lwip/err.h"
#include "lwip/sys.h"
#include "config.h"
#include "wifiMng.h"


static const char *TAG = "WIFI_MNG";
/* Enable send management frames */
extern int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3){
    return 0;
}


static void wifi_event_handler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data)
{
    if (event_id == WIFI_EVENT_AP_STACONNECTED) 
    {
        wifi_event_ap_staconnected_t* event = (wifi_event_ap_staconnected_t*) event_data;
        ESP_LOGI(TAG, "station "MACSTR" join, AID=%d", MAC2STR(event->mac), event->aid);
    } 
    else if (event_id == WIFI_EVENT_AP_STADISCONNECTED)
    {
        wifi_event_ap_stadisconnected_t* event = (wifi_event_ap_stadisconnected_t*) event_data;
        ESP_LOGI(TAG, "station "MACSTR" leave, AID=%d, reason=NULL", MAC2STR(event->mac), event->aid);
    }
}


static esp_err_t set_wifi_region() {
    wifi_country_t country = {
        .cc = "CN",      // Codice paese (EU per Europa)
        .schan = 1,      // Canale iniziale
        .nchan = 14,     // Numero di canali (1-13 per EU)
        .policy = WIFI_COUNTRY_POLICY_MANUAL // Configurazione manual
    };

    esp_err_t err = esp_wifi_set_country(&country);
    return err;
}


esp_err_t wifi_init(void)
{
    /* Disable wifi logs */
    esp_log_level_set("wifi", ESP_LOG_WARN);
    
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_ap();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    ESP_ERROR_CHECK(esp_wifi_set_max_tx_power(68));
#ifndef CONFIG_IDF_TARGET_ESP32C5
    ESP_ERROR_CHECK(esp_wifi_set_bandwidth(WIFI_IF_AP, WIFI_BW_HT20));
    ESP_ERROR_CHECK(esp_wifi_set_bandwidth(WIFI_IF_STA, WIFI_BW_HT20));
 #endif
    ESP_ERROR_CHECK(set_wifi_region());
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, NULL));
    return ESP_OK;
}


void wifi_start_softap(void)
{
    wifi_config_t wifi_config = {
        .ap = {
            .ssid = DEFAULT_WIFI_SSID,
            .password = DEFAULT_WIFI_PASS,
            .ssid_len = strlen(DEFAULT_WIFI_SSID),
            .channel = DEFAULT_WIFI_CHAN,
            .authmode = DEFAULT_WIFI_AUTH,
            .beacon_interval = 500,
            .max_connection = DEFAULT_WIFI_MAX_CONN,
            .pmf_cfg = {
                    /* Cannot set pmf to required when in wpa-wpa2 mixed mode! Setting pmf to optional mode. */
                    .required = false,
                    .capable = false
            }
        }
    };

    if(read_string_from_flash(WIFI_SSID_KEY, (char *)&wifi_config.ap.ssid) != ESP_OK )
    {
        strcpy((char *)&wifi_config.ap.ssid, DEFAULT_WIFI_SSID);
    }
    wifi_config.ap.ssid_len = strlen((char *)&wifi_config.ap.ssid);
    if(read_string_from_flash(WIFI_PASS_KEY, (char *)&wifi_config.ap.password) != ESP_OK )
    {
        strcpy((char *)&wifi_config.ap.password, DEFAULT_WIFI_PASS);
    }
    if(read_int_from_flash(WIFI_CHAN_KEY, (int32_t *)&wifi_config.ap.channel) != ESP_OK )
    {
        wifi_config.ap.channel = DEFAULT_WIFI_CHAN;
    }
    wifi_config.ap.authmode = DEFAULT_WIFI_AUTH;

    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &wifi_config));
}


void wifi_ap_clone(wifi_config_t *wifi_config, uint8_t *bssid)
{
    if( bssid != NULL )
    {
        ESP_ERROR_CHECK(esp_wifi_set_mac(WIFI_IF_AP, bssid));
    }
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, wifi_config));
}