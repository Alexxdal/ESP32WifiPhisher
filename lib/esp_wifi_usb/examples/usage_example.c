#include "esp_wifi_usb.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "esp_timer.h"

static const char *TAG = "APP";

static uint8_t s_test_beacon[] = {
    /* ---- MAC Header (24 bytes) ---- */
    0x80, 0x00,                         // 0-1: Frame Control (Beacon)
    0x00, 0x00,                         // 2-3: Duration
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 4-9: Destination (Broadcast)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 10-15: Source
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 16-21: BSSID
    0x00, 0x00,                         // 22-23: Sequence Control
    
    /* ---- Beacon Body ---- */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 24-31: Timestamp
    0x64, 0x00,                         // 32-33: Beacon Interval: 100 TU
    0x01, 0x00,                         // 34-35: Capability: ESS (Access Point)
    
    /* ---- Information Elements ---- */
    // SSID: "ESP32_RTL"
    0x00, 0x09, 'E', 'S', 'P', '3', '2', '_', 'R', 'T', 'L',
    // Supported Rates: 1, 2, 5.5, 11 Mbps
    0x01, 0x04, 0x82, 0x84, 0x8B, 0x96,
    // DSSS Parameter Set: Channel 1
    0x03, 0x01, 0x01,
    // TIM (Traffic Indication Map)
    0x05, 0x04, 0x00, 0x01, 0x00, 0x00
};

static void wifi_usb_sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *frame = pkt->payload;

    if (pkt->rx_ctrl.sig_len < 24) return;   /* header 802.11 (without QoS/HT) */

    uint8_t subtype = (frame[0] >> 4) & 0xF;
    const uint8_t *addr2 = frame + 10;

    ESP_LOGI(TAG, "[ch %u] rssi=%d tipo=%d subtype=%d len=%u da %02X:%02X:%02X:%02X:%02X:%02X%s%s",
             pkt->rx_ctrl.channel, pkt->rx_ctrl.rssi, type, subtype, pkt->rx_ctrl.sig_len,
             addr2[0], addr2[1], addr2[2], addr2[3], addr2[4], addr2[5],
             pkt->rx_ctrl.crc_err ? " [CRC ERR]" : "",
             pkt->rx_ctrl.icv_err ? " [ICV ERR]" : "");
}

void app_main(void)
{
    esp_err_t err = esp_wifi_usb_init(portMAX_DELAY);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_wifi_usb_init failed: %d", err);
    }

    esp_wifi_usb_set_promiscuous_rx_cb(wifi_usb_sniffer_cb);
    esp_wifi_usb_set_promiscuous(true);
    esp_wifi_usb_set_channel(1);
    esp_wifi_usb_set_tx_power(50);

    ESP_ERROR_CHECK(esp_wifi_usb_start());

    uint8_t mac[6];
    esp_wifi_usb_get_mac(mac);
    
    uint8_t beacon[sizeof(s_test_beacon)];
    memcpy(beacon, s_test_beacon, sizeof(s_test_beacon));
    
    memcpy(&beacon[10], mac, 6);
    memcpy(&beacon[16], mac, 6);

    uint16_t seq_num = 0;
    
    while(true) 
    {
        seq_num++;
        uint16_t seq_ctrl = (seq_num << 4);
        beacon[22] = seq_ctrl & 0xFF;
        beacon[23] = (seq_ctrl >> 8) & 0xFF;

        uint64_t tsf = esp_timer_get_time();
        memcpy(&beacon[24], &tsf, 8);

        esp_err_t err = esp_wifi_usb_80211_tx(beacon, sizeof(beacon), false);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "TX failed");
        }
        
        vTaskDelay(pdMS_TO_TICKS(50));
    }
}