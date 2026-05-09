#include <string.h>
#include <stdint.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <esp_mac.h>
#include <esp_event.h>
#include <esp_log.h>
//#include "esp_private/wifi.h" 
#include "config.h"
#include "wifiMng.h"
#include "nvs_keys.h"
#include "utils.h"


static const char *TAG = "WIFI_MNG";

static volatile uint32_t g_tx_packets_success = 0;
static volatile uint32_t g_tx_packets_dropped = 0;
/* --- PPS VARIABLES--- */
static volatile uint32_t g_tx_pps = 0;
static uint32_t last_tx_success_count = 0;
static TimerHandle_t pps_timer = NULL;


static void IRAM_ATTR wifi_80211_tx_done_cb(const esp_80211_tx_info_t *tx_info) {
    if (tx_info->tx_status == WIFI_SEND_SUCCESS) {
        g_tx_packets_success++;
    } else {
        g_tx_packets_dropped++;
    }
}


static void pps_timer_cb(TimerHandle_t xTimer) 
{
    uint32_t current_count = g_tx_packets_success;
    g_tx_pps = current_count - last_tx_success_count;
    last_tx_success_count = current_count;
}


/* Enable send management frames */
extern int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3){
    return 0;
}


static void wifi_event_handler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data)
{
    if(event_base != WIFI_EVENT) return;

    if (event_id == WIFI_EVENT_AP_STACONNECTED) 
    {
        wifi_event_ap_staconnected_t* event = (wifi_event_ap_staconnected_t*) event_data;
        ESP_LOGI(TAG, "Station ("MACSTR") connected to AP, AID=%d", MAC2STR(event->mac), event->aid);
    } 
    else if (event_id == WIFI_EVENT_AP_STADISCONNECTED)
    {
        wifi_event_ap_stadisconnected_t* event = (wifi_event_ap_stadisconnected_t*) event_data;
        ESP_LOGI(TAG, "Station ("MACSTR") disconnected from AP, AID=%d, reason=%d", MAC2STR(event->mac), event->aid, event->reason);
    }
}


static esp_err_t set_wifi_region() {
    wifi_country_t country = {
        .cc = "CN",      // Codice paese (EU per Europa)
        .schan = 1,      // Canale iniziale
        .nchan = 14,     // Numero di canali (1-13 per EU)
        .policy = WIFI_COUNTRY_POLICY_AUTO,
        #if CONFIG_SOC_WIFI_SUPPORT_5G
        .wifi_5g_channel_mask = 0
        #endif
    };

    esp_err_t err = esp_wifi_set_country(&country);
    return err;
}


static esp_err_t wifi_set_tx_rate(wifi_interface_t ifx, wifi_phy_rate_t target_rate) 
{
    wifi_tx_rate_config_t rate_config = {
        .ersu = false,
        .dcm = false,
        .rate = target_rate
    };

    if (target_rate >= WIFI_PHY_RATE_1M_L && target_rate <= WIFI_PHY_RATE_11M_S) {
        // 0x00 - 0x07 standard 802.11b
        rate_config.phymode = WIFI_PHY_MODE_11B;
        ESP_LOGI(TAG, "Setting TX Rate to 802.11b mode (%s)", wifi_rate_to_str(target_rate));
        
    } else if (target_rate >= WIFI_PHY_RATE_48M && target_rate <= WIFI_PHY_RATE_9M) {
        // 0x08 - 0x0F standard 802.11g
        rate_config.phymode = WIFI_PHY_MODE_11G;
        ESP_LOGI(TAG, "Setting TX Rate to 802.11g mode (%s)", wifi_rate_to_str(target_rate));
        
    } else {
        // 0x10 in poi sono indici MCS (802.11n / HT20)
        rate_config.phymode = WIFI_PHY_MODE_HT20;
        ESP_LOGI(TAG, "Setting TX Rate to 802.11n (HT20) mode (%s)", wifi_rate_to_str(target_rate));
    }

    esp_err_t err = esp_wifi_config_80211_tx(ifx, &rate_config);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to set TX rate: %s", esp_err_to_name(err));
    }
    return err;
}


esp_err_t wifi_init(void)
{
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_ap();
    esp_netif_create_default_wifi_sta();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    ESP_ERROR_CHECK(set_wifi_region());
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));
    ESP_ERROR_CHECK(esp_wifi_set_max_tx_power(84));

    wifi_phy_rate_t target_rate = 0;
    if(read_int_from_nvs(WIFI_TX_RATE_KEY, (int32_t *)&target_rate) != ESP_OK )
    {
        target_rate = DEFAULT_WIFI_TX_RATE;
    }
    ESP_ERROR_CHECK(wifi_set_tx_rate(WIFI_IF_STA, target_rate));

#if CONFIG_SOC_WIFI_SUPPORT_5G
    wifi_bandwidths_t bands = {
        .ghz_2g = WIFI_BW_HT20,
        .ghz_5g = WIFI_BW_HT20
    };
    ESP_ERROR_CHECK(esp_wifi_set_bandwidths(WIFI_IF_AP, &bands));
    ESP_ERROR_CHECK(esp_wifi_set_bandwidths(WIFI_IF_STA, &bands));
#else
    ESP_ERROR_CHECK(esp_wifi_set_bandwidth(WIFI_IF_AP, WIFI_BW_HT20));
    ESP_ERROR_CHECK(esp_wifi_set_bandwidth(WIFI_IF_STA, WIFI_BW_HT20));
#endif

    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, NULL));

    /* Callback for frame statistics */
    esp_err_t err = esp_wifi_register_80211_tx_cb(wifi_80211_tx_done_cb);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to register TX callback: %s", esp_err_to_name(err));
    }

    /* Timer for PPS Calculation */
    pps_timer = xTimerCreate("pps_timer", pdMS_TO_TICKS(1000), pdTRUE, (void *)0, pps_timer_cb);
    if (pps_timer != NULL) {
        xTimerStart(pps_timer, 0);
    }

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
            .beacon_interval = 100,
            .max_connection = DEFAULT_WIFI_MAX_CONN,
            .dtim_period = 1,
            .pmf_cfg = {
                    /* Cannot set pmf to required when in wpa-wpa2 mixed mode! Setting pmf to optional mode. */
                    .required = false,
                    .capable = false
            }
        }
    };

    if(read_string_from_nvs(WIFI_SSID_KEY, (char *)&wifi_config.ap.ssid) != ESP_OK )
    {
        strcpy((char *)&wifi_config.ap.ssid, DEFAULT_WIFI_SSID);
    }
    wifi_config.ap.ssid_len = strlen((char *)&wifi_config.ap.ssid);
    if(read_string_from_nvs(WIFI_PASS_KEY, (char *)&wifi_config.ap.password) != ESP_OK )
    {
        strcpy((char *)&wifi_config.ap.password, DEFAULT_WIFI_PASS);
    }
    if(read_int_from_nvs(WIFI_CHAN_KEY, (int32_t *)&wifi_config.ap.channel) != ESP_OK )
    {
        wifi_config.ap.channel = DEFAULT_WIFI_CHAN;
    }
    wifi_config.ap.authmode = DEFAULT_WIFI_AUTH;

    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &wifi_config));
    
    /* Force only 11b and 11g for max stability */
    #if CONFIG_SOC_WIFI_SUPPORT_5G
    wifi_protocols_t protos = {
        .ghz_2g = WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G,
        .ghz_5g = WIFI_PROTOCOL_11A
    };
    esp_err_t err_prot = esp_wifi_set_protocols(WIFI_IF_AP, &protos);
    if(err_prot != ESP_OK) {
        ESP_LOGE(TAG, "Failed to set AP protocols (dual-band API): %s", esp_err_to_name(err_prot));
    }
#else
    esp_err_t err_prot = esp_wifi_set_protocol(WIFI_IF_AP, WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G);
    if(err_prot != ESP_OK) {
        ESP_LOGE(TAG, "Failed to set AP protocol (single-band API): %s", esp_err_to_name(err_prot));
    }
#endif
}


void wifi_ap_clone(wifi_config_t *wifi_config, uint8_t *bssid)
{
    if( bssid != NULL )
    {
        ESP_ERROR_CHECK(esp_wifi_set_mac(WIFI_IF_AP, bssid));
    }
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, wifi_config));
}


esp_err_t wifi_set_channel_safe(uint8_t new_channel)
{
    if( new_channel < 1 ) {
        return ESP_ERR_INVALID_ARG;
    }

    #if !CONFIG_SOC_WIFI_SUPPORT_5G
    if( new_channel > 14 ) {
        ESP_LOGW(TAG, "CSA Target channel=%d, This device does not support 5G channels", new_channel);
        return ESP_ERR_INVALID_ARG;
    }
    #endif

    uint8_t current_channel = 0;
    wifi_second_chan_t second = WIFI_SECOND_CHAN_NONE;
    esp_wifi_get_channel(&current_channel, &second);
    if(current_channel == new_channel) {
        ESP_LOGD(TAG, "Already on channel %d, no switch needed", new_channel);
        return ESP_OK; // No need to switch
    }

    wifi_sta_list_t station_list;
    esp_err_t err = esp_wifi_ap_get_sta_list(&station_list);
    if (err == ESP_OK && station_list.num > 0) {
        ESP_LOGW(TAG, "Forcing deauth of %d clients to switch channel", station_list.num);
        err = esp_wifi_deauth_sta(0);
        if( err != ESP_OK) {
            ESP_LOGW(TAG, "Failed to deauth clients: %s", esp_err_to_name(err));
        }
        vTaskDelay(pdMS_TO_TICKS(100)); 
    }
    
    err = esp_wifi_set_channel(new_channel, WIFI_SECOND_CHAN_NONE);
    if(err != ESP_OK) {
        ESP_LOGW(TAG, "Channel switch failed (%s) - Radio locked", esp_err_to_name(err));
    }
    return err;
}


esp_err_t wifi_set_temporary_channel(uint8_t new_channel, uint32_t window)
{
    wifi_roc_req_t roc_req = {
        .ifx = WIFI_IF_STA,
        .type = WIFI_ROC_REQ,
        .channel = new_channel,
        .sec_channel = WIFI_SECOND_CHAN_NONE,
        .wait_time_ms = window,
        .rx_cb = NULL,
        .done_cb = NULL
    };

    return esp_wifi_remain_on_channel(&roc_req);
}


uint32_t wifi_get_sent_frames(void) 
{
    return g_tx_packets_success;
}


uint32_t wifi_get_dropped_frames(void) 
{
    return g_tx_packets_dropped;
}


void wifi_dropped_frame_increment(void)
{
    g_tx_packets_dropped++;
}


void wifi_sent_frame_increment(void)
{
    g_tx_packets_success++;
}


void wifi_reset_frame_counters(void)
{
    g_tx_packets_success = 0;
    g_tx_packets_dropped = 0;
    g_tx_pps = 0;
}


uint32_t wifi_get_frame_pps(void) 
{
    return g_tx_pps;
}