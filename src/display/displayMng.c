#include <string.h>
#include <stdio.h>
#include "esp_log.h"
#include "esp_err.h"
#include "TaskManager.h"
#include "displayMng.h"

static const char __attribute__((unused)) *TAG = "DISPLAY_MNG";

#if defined(TARGET_CARDPUTER)

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "freertos/semphr.h"
#include "driver/spi_master.h"
#include "driver/gpio.h"
#include "esp_lcd_panel_io.h"
#include "esp_lcd_panel_dev.h"
#include "esp_lcd_panel_ops.h"
#include "esp_lcd_panel_vendor.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include "esp_wifi.h"
#include "wifiMng.h"
#include "networking.h"
#include "ble_sniffer.h"
#include "ble_spam.h"
#include "evil_twin.h"
#include "deauther.h"
#include "sniffer.h"
#include "karma_attack.h"
#include "font8x8_min.h"

/* --- COLORS (RGB565 Swapped for SPI Endianness - CASTED PROPERLY) --- */
#define SWAP16(c)   ((uint16_t)((((uint16_t)(c) & 0xFF00) >> 8) | (((uint16_t)(c) & 0x00FF) << 8)))
#define C_WHITE     0xFFFF
#define C_BLACK     0x0000
#define C_RED       SWAP16(0xF800)
#define C_GREEN     SWAP16(0x07E0)
#define C_BLUE      SWAP16(0x001F)
#define C_YELLOW    SWAP16(0xFFE0)
#define C_CYAN      SWAP16(0x07FF)
#define C_MAGENTA   SWAP16(0xF81F)
#define C_ORANGE    SWAP16(0xFD20)

/* --- HARDWARE DEFINES --- */
#define TFT_PIN_MOSI        35
#define TFT_PIN_SCLK        36
#define TFT_PIN_CS          37
#define TFT_PIN_DC          34
#define TFT_PIN_RST         33
#define TFT_PIN_BL          38

#define DISP_WIDTH          240
#define DISP_HEIGHT         135
#define DISP_GAP_X          40
#define DISP_GAP_Y          53
#define DISP_SPI_HOST       SPI2_HOST
#define DISP_SPI_HZ         (40 * 1000 * 1000)

#define GLYPH_W             8
#define GLYPH_H             8
#define CHAR_PITCH          9     /* 8px glyph + 1px gap */
#define LINE_MAX_CHARS      (DISP_WIDTH / CHAR_PITCH)   /* 26 */
#define ROW_HEIGHT          13
#define ROW_Y_START         2

#define DISPLAY_TASK_STACK  4096
#define DISPLAY_TASK_PRIO   3
#define DISPLAY_REFRESH_MS  1000
#define DISPLAY_EVT_TASK_EXITED BIT0

static esp_lcd_panel_handle_t  s_panel = NULL;
static esp_lcd_panel_io_handle_t s_io = NULL;
static TaskHandle_t            s_task_handle = NULL;
static EventGroupHandle_t      s_evt = NULL;
static volatile bool           s_running = false;
static SemaphoreHandle_t       s_trans_done_sem = NULL;

static uint16_t s_line_buf[DISP_WIDTH * ROW_HEIGHT];

static bool on_color_trans_done(esp_lcd_panel_io_handle_t panel_io, esp_lcd_panel_io_event_data_t *edata, void *user_ctx)
{
    BaseType_t high_task_wakeup = pdFALSE;
    xSemaphoreGiveFromISR(s_trans_done_sem, &high_task_wakeup);
    return high_task_wakeup == pdTRUE;
}

static void display_clear(void)
{
    memset(s_line_buf, 0, sizeof(s_line_buf)); // Riempie di C_BLACK
    for (int y = 0; y < DISP_HEIGHT; y += ROW_HEIGHT) {
        int end_y = y + ROW_HEIGHT;
        if (end_y > DISP_HEIGHT) end_y = DISP_HEIGHT;
        esp_lcd_panel_draw_bitmap(s_panel, 0, y, DISP_WIDTH, end_y, s_line_buf);
        xSemaphoreTake(s_trans_done_sem, portMAX_DELAY);
    }
}

static esp_err_t display_hw_init(void)
{
    gpio_config_t bl_cfg = {
        .pin_bit_mask = (1ULL << TFT_PIN_BL),
        .mode = GPIO_MODE_OUTPUT,
    };
    gpio_config(&bl_cfg);
    gpio_set_level(TFT_PIN_BL, 0);

    if (s_trans_done_sem == NULL) {
        s_trans_done_sem = xSemaphoreCreateBinary();
        if (s_trans_done_sem == NULL) return ESP_ERR_NO_MEM;
    }

    spi_bus_config_t buscfg = {
        .mosi_io_num = TFT_PIN_MOSI,
        .miso_io_num = -1,
        .sclk_io_num = TFT_PIN_SCLK,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
        .max_transfer_sz = sizeof(s_line_buf),
    };
    esp_err_t err = spi_bus_initialize(DISP_SPI_HOST, &buscfg, SPI_DMA_CH_AUTO);
    if (err != ESP_OK) return err;

    esp_lcd_panel_io_spi_config_t io_config = {
        .cs_gpio_num = TFT_PIN_CS,
        .dc_gpio_num = TFT_PIN_DC,
        .spi_mode = 0,
        .pclk_hz = DISP_SPI_HZ,
        .trans_queue_depth = 10,
        .lcd_cmd_bits = 8,
        .lcd_param_bits = 8,
        .on_color_trans_done = on_color_trans_done,
    };
    err = esp_lcd_new_panel_io_spi((esp_lcd_spi_bus_handle_t)DISP_SPI_HOST, &io_config, &s_io);
    if (err != ESP_OK) {
        spi_bus_free(DISP_SPI_HOST);
        return err;
    }

    esp_lcd_panel_dev_config_t panel_config = {
        .reset_gpio_num = TFT_PIN_RST,
        .rgb_ele_order = LCD_RGB_ELEMENT_ORDER_RGB,
        .bits_per_pixel = 16,
    };
    err = esp_lcd_new_panel_st7789(s_io, &panel_config, &s_panel);
    if (err != ESP_OK) {
        esp_lcd_panel_io_del(s_io);
        spi_bus_free(DISP_SPI_HOST);
        return err;
    }

    esp_lcd_panel_reset(s_panel);
    esp_lcd_panel_init(s_panel);
    esp_lcd_panel_invert_color(s_panel, true);
    esp_lcd_panel_swap_xy(s_panel, true);
    esp_lcd_panel_mirror(s_panel, true, false);
    esp_lcd_panel_set_gap(s_panel, DISP_GAP_X, DISP_GAP_Y);
    esp_lcd_panel_disp_on_off(s_panel, true);
    
    display_clear();
    gpio_set_level(TFT_PIN_BL, 1);
    return ESP_OK;
}

static void display_hw_deinit(void)
{
    gpio_set_level(TFT_PIN_BL, 0);
    if (s_panel) { esp_lcd_panel_del(s_panel); s_panel = NULL; }
    if (s_io) { esp_lcd_panel_io_del(s_io); s_io = NULL; }
    spi_bus_free(DISP_SPI_HOST);
    if (s_trans_done_sem) { vSemaphoreDelete(s_trans_done_sem); s_trans_done_sem = NULL; }
}

static void draw_text_line(int y, const char *text, uint16_t color)
{
    memset(s_line_buf, 0, sizeof(s_line_buf));
    size_t len = strlen(text);
    if (len > LINE_MAX_CHARS) len = LINE_MAX_CHARS; 

    int y_offset = (ROW_HEIGHT - GLYPH_H) / 2; 

    for (size_t ci = 0; ci < len; ci++) {
        const uint8_t *glyph = font8x8_min_get_row(text[ci]);
        int x0 = 2 + (ci * CHAR_PITCH); 
        
        for (int row = 0; row < GLYPH_H; row++) {
            uint8_t bits = glyph[row];
            for (int col = 0; col < GLYPH_W; col++) {
                if (bits & (1 << col)) {   
                    s_line_buf[(row + y_offset) * DISP_WIDTH + x0 + col] = color;
                }
            }
        }
    }

    int end_y = y + ROW_HEIGHT;
    if (end_y > DISP_HEIGHT) end_y = DISP_HEIGHT;
    esp_lcd_panel_draw_bitmap(s_panel, 0, y, DISP_WIDTH, end_y, s_line_buf);
    xSemaphoreTake(s_trans_done_sem, portMAX_DELAY);
}

static const char* get_deauth_name_str(deauther_attack_type_t t) {
    switch(t) {
        case DEAUTHER_ATTACK_DEAUTH_FRAME: return "DEAUTH";
        case DEAUTHER_ATTACK_DISASSOC_FRAME: return "DISASSOC";
        case DEAUTHER_ATTACK_BROADCAST_FLOOD: return "BCAST FLD";
        case DEAUTHER_ATTACK_AUTH_FLOOD: return "AUTH FLD";
        case DEAUTHER_ATTACK_ASSOC_FLOOD: return "ASSOC FLD";
        case DEAUTHER_ATTACK_CSA_SPOOFING: return "CSA SPOOF";
        case DEAUTHER_ATTACK_EAPOL_LOGOFF: return "EAP LOGOFF";
        case DEAUTHER_ATTACK_EAPOL_START: return "EAP START";
        case DEAUTHER_ATTACK_EAP_FAILURE: return "EAP FAIL";
        case DEAUTHER_ATTACK_EAP_ID_SPAM: return "EAP ID SPAM";
        case DEAUTHER_ATTACK_HANDSHAKE_BLOCK: return "HS BLOCK";
        case DEAUTHER_ATTACK_WPA3_SAE_FLOOD: return "WPA3 SAE";
        case DEAUTHER_ATTACK_PMF_DOWNGRADE: return "PMF DWNGRD";
        case DEAUTHER_ATTACK_NAV_ABUSE: return "NAV ABUSE";
        case DEAUTHER_ATTACK_BEACON_SPAM: return "BCON SPAM";
        default: return "UNKNOWN";
    }
}

static void display_task(void *param)
{
    char line[64];
    if (s_evt) xEventGroupClearBits(s_evt, DISPLAY_EVT_TASK_EXITED);

    while (s_running) {
        int y = ROW_Y_START;

        bool et_on = (evil_twin_attack_get_status() != EVIL_TWIN_ATTACK_STATUS_IDLE);
        bool de_on = deauther_is_running();
        bool ka_on = (karma_attack_get_status() != KARMA_ATTACK_STATUS_IDLE);
        bool ble_sniff = ble_sniffer_is_running();
        bool ble_spam = ble_spam_is_running();

        size_t free_ram = heap_caps_get_free_size(MALLOC_CAP_DEFAULT);
        int64_t time_s = esp_timer_get_time() / 1000000;
        int hh = (int)(time_s / 3600);
        int mm = (int)((time_s % 3600) / 60);
        int ss = (int)(time_s % 60);

        if (et_on) 
        {
            target_info_t *t = target_get(TARGET_INFO_EVIL_TWIN);
            int hs = wifi_sniffer_get_handshake_status_for_target(t->bssid);
            
            snprintf(line, sizeof(line), ">> EVIL TWIN ACTIVE <<"); draw_text_line(y, line, C_RED); y += ROW_HEIGHT;
            snprintf(line, sizeof(line), "Tgt: %.21s", t->ssid); draw_text_line(y, line, C_WHITE); y += ROW_HEIGHT;
            snprintf(line, sizeof(line), "Ch : %d", t->channel); draw_text_line(y, line, C_CYAN); y += ROW_HEIGHT;
            snprintf(line, sizeof(line), "Tx : %lu", wifi_get_sent_frames()); draw_text_line(y, line, C_YELLOW); y += ROW_HEIGHT;
            snprintf(line, sizeof(line), "PPS: %lu", wifi_get_frame_pps()); draw_text_line(y, line, C_YELLOW); y += ROW_HEIGHT;
            
            if (hs == 2)      { snprintf(line, sizeof(line), "HS : CAPTURED (4-WAY)"); draw_text_line(y, line, C_GREEN); }
            else if (hs == 1) { snprintf(line, sizeof(line), "HS : CAPTURED (PMKID)"); draw_text_line(y, line, C_ORANGE); }
            else              { snprintf(line, sizeof(line), "HS : WAITING...");       draw_text_line(y, line, C_WHITE); }
            y += ROW_HEIGHT;
        } 
        else if (ka_on) 
        {
            target_info_t *t = target_get(TARGET_INFO_KARMA_ATTACK);
            karma_attack_status_t ks = karma_attack_get_status();
            
            snprintf(line, sizeof(line), ">>>  KARMA ATTACK  <<<"); draw_text_line(y, line, C_MAGENTA); y += ROW_HEIGHT;
            
            if (ks == KARMA_ATTACK_STATUS_PROBE_SCANNING) {
                snprintf(line, sizeof(line), "Mode: SCAN PROBES"); draw_text_line(y, line, C_ORANGE); y += ROW_HEIGHT;
                probe_request_list_t pl = {0};
                wifi_sniffer_get_probes(&pl);
                snprintf(line, sizeof(line), "Found: %d", pl.num_probes); draw_text_line(y, line, C_WHITE); y += ROW_HEIGHT;
            } else {
                snprintf(line, sizeof(line), "Mode: ACTIVE (AP)"); draw_text_line(y, line, C_GREEN); y += ROW_HEIGHT;
                snprintf(line, sizeof(line), "SSID: %.20s", t->ssid); draw_text_line(y, line, C_WHITE); y += ROW_HEIGHT;
                snprintf(line, sizeof(line), "Ch  : %d", t->channel); draw_text_line(y, line, C_CYAN); y += ROW_HEIGHT;
            }
        } 
        else if (de_on) 
        {
            target_info_t *t = target_get(TARGET_INFO_DEAUTHER);
            // Uso diretto di memcmp invece della funzione isMacBroadcast per prevenire implicite
            bool broadcast = (memcmp(t->bssid, "\xff\xff\xff\xff\xff\xff", 6) == 0);
            deauther_attack_type_t atk_type = deauther_get_attack_type();
            
            snprintf(line, sizeof(line), ">>>  DEAUTH ACTIVE <<<"); draw_text_line(y, line, C_RED); y += ROW_HEIGHT;
            snprintf(line, sizeof(line), "Type: %s", get_deauth_name_str(atk_type)); draw_text_line(y, line, C_ORANGE); y += ROW_HEIGHT;

            if (broadcast) {
                snprintf(line, sizeof(line), "Tgt : BROADCAST / ALL"); draw_text_line(y, line, C_WHITE); y += ROW_HEIGHT;
                if (t->channel == 0) {
                    snprintf(line, sizeof(line), "Ch  : HOPPING");
                } else {
                    snprintf(line, sizeof(line), "Ch  : %d", t->channel);
                }
                draw_text_line(y, line, C_CYAN); y += ROW_HEIGHT;
            } else {
                uint8_t assoc_cli = wifi_sniffer_get_associated_client_count(t->bssid);
                int8_t rssi = wifi_sniffer_get_ap_rssi(t->bssid);
                snprintf(line, sizeof(line), "Tgt : %.20s", t->ssid); draw_text_line(y, line, C_WHITE); y += ROW_HEIGHT;
                snprintf(line, sizeof(line), "Ch  : %d | Rssi: %d", t->channel, rssi); draw_text_line(y, line, C_CYAN); y += ROW_HEIGHT;
                snprintf(line, sizeof(line), "Cli : %d", assoc_cli); draw_text_line(y, line, C_GREEN); y += ROW_HEIGHT; 
            }
            
            snprintf(line, sizeof(line), "Tx  : %lu pkts", wifi_get_sent_frames()); draw_text_line(y, line, C_YELLOW); y += ROW_HEIGHT;
            snprintf(line, sizeof(line), "Rate: %lu pps", wifi_get_frame_pps()); draw_text_line(y, line, C_YELLOW); y += ROW_HEIGHT;
            
            if (!broadcast) {
                int hs = wifi_sniffer_get_handshake_status_for_target(t->bssid);
                if (hs == 2)      { snprintf(line, sizeof(line), "HS : CAPTURED (4-WAY)"); draw_text_line(y, line, C_GREEN); }
                else if (hs == 1) { snprintf(line, sizeof(line), "HS : CAPTURED (PMKID)"); draw_text_line(y, line, C_ORANGE); }
                else              { snprintf(line, sizeof(line), "HS : WAITING...");       draw_text_line(y, line, C_WHITE); }
                y += ROW_HEIGHT; // Aggiorna la Y anche dopo l'handshake
            }
        }
        else if (ble_sniff || ble_spam) 
        {
            snprintf(line, sizeof(line), ">>> BLUETOOTH MODE <<<"); draw_text_line(y, line, C_BLUE); y += ROW_HEIGHT;
            snprintf(line, sizeof(line), "Sniffer: %s", ble_sniff ? "ON" : "OFF"); draw_text_line(y, line, ble_sniff ? C_GREEN : C_WHITE); y += ROW_HEIGHT;
            snprintf(line, sizeof(line), "Spammer: %s", ble_spam ? "ON" : "OFF"); draw_text_line(y, line, ble_spam ? C_RED : C_WHITE); y += ROW_HEIGHT;
            
            if (ble_sniff) {
                ble_sniffer_stats_t bs;
                ble_sniffer_get_stats(&bs);
                snprintf(line, sizeof(line), "Devices: %u", bs.unique_devices); draw_text_line(y, line, C_CYAN); y += ROW_HEIGHT;
                snprintf(line, sizeof(line), "Packets: %lu", (unsigned long)bs.total_packets); draw_text_line(y, line, C_YELLOW); y += ROW_HEIGHT;
            }
        } 
        else 
        {
            snprintf(line, sizeof(line), "ESP32 Audit v%s", APP_VERSION); draw_text_line(y, line, C_CYAN); y += ROW_HEIGHT;
            
            wifi_config_t ap_cfg;
            char ap_ssid[33] = "--";
            if (esp_wifi_get_config(WIFI_IF_AP, &ap_cfg) == ESP_OK) {
                snprintf(ap_ssid, sizeof(ap_ssid), "%.21s", ap_cfg.ap.ssid);
            }
            wifi_sta_list_t ap_clients;
            uint8_t ap_client_count = 0;
            if (esp_wifi_ap_get_sta_list(&ap_clients) == ESP_OK) {
                ap_client_count = ap_clients.num;
            }
            snprintf(line, sizeof(line), "AP : %s (%d cli)", ap_ssid, ap_client_count); draw_text_line(y, line, C_GREEN); y += ROW_HEIGHT;

            char sta_ssid[33] = "Disconnected";
            char ip_str[16] = "--";
            if (wifi_is_connected()) {
                wifi_config_t sta_cfg;
                if (esp_wifi_get_config(WIFI_IF_STA, &sta_cfg) == ESP_OK) {
                    snprintf(sta_ssid, sizeof(sta_ssid), "%.20s", sta_cfg.sta.ssid);
                }
                if (networking_has_ip()) {
                    esp_netif_ip_info_t *ip_info = networking_get_ip_info();
                    snprintf(ip_str, sizeof(ip_str), IPSTR, IP2STR(&ip_info->ip));
                }
            }
            snprintf(line, sizeof(line), "STA: %s", sta_ssid); draw_text_line(y, line, wifi_is_connected() ? C_GREEN : C_WHITE); y += ROW_HEIGHT;
            snprintf(line, sizeof(line), "IP : %s", ip_str); draw_text_line(y, line, C_YELLOW); y += ROW_HEIGHT;

            int ap_count = wifi_sniffer_get_aps_count();
            int cli_count = wifi_sniffer_get_clients_count();
            ble_sniffer_stats_t bs;
            ble_sniffer_get_stats(&bs);
            
            snprintf(line, sizeof(line), "FND:%d AP|%d CL|%u BL", ap_count, cli_count, bs.unique_devices);
            draw_text_line(y, line, C_ORANGE); y += ROW_HEIGHT;
        }

        while(y < ROW_Y_START + (8 * ROW_HEIGHT)) {
            draw_text_line(y, "", C_BLACK);
            y += ROW_HEIGHT;
        }

        y = ROW_Y_START + (8 * ROW_HEIGHT);
        snprintf(line, sizeof(line), "Up %02d:%02d:%02d RM:%uK", hh, mm, ss, (unsigned)(free_ram / 1024));
        draw_text_line(y, line, C_GREEN); 
        y += ROW_HEIGHT;

        while(y <= DISP_HEIGHT - GLYPH_H) {
            draw_text_line(y, "", C_BLACK);
            y += ROW_HEIGHT;
        }

        uint32_t waited = 0;
        while (s_running && waited < DISPLAY_REFRESH_MS) {
            uint32_t step = (DISPLAY_REFRESH_MS - waited < 100) ? (DISPLAY_REFRESH_MS - waited) : 100;
            vTaskDelay(pdMS_TO_TICKS(step));
            waited += step;
        }
    }

    if (s_evt) xEventGroupSetBits(s_evt, DISPLAY_EVT_TASK_EXITED);
    task_manager_unregister_current_task();
    vTaskDelete(NULL);
}

esp_err_t display_init(void)
{
    if (s_task_handle != NULL) return ESP_OK;

    esp_err_t err = display_hw_init();
    if (err != ESP_OK) return err;

    if (s_evt == NULL) {
        s_evt = xEventGroupCreate();
        if (s_evt == NULL) {
            display_hw_deinit();
            return ESP_ERR_NO_MEM;
        }
    }

    s_running = true;
    err = task_manager_create_task(display_task, "display_task",
                                    DISPLAY_TASK_STACK, NULL,
                                    DISPLAY_TASK_PRIO, &s_task_handle);
    if (err != ESP_OK) {
        s_running = false;
        display_hw_deinit();
        return err;
    }

    return ESP_OK;
}

esp_err_t display_deinit(void)
{
    if (s_task_handle == NULL) return ESP_OK;

    s_running = false;
    EventBits_t bits = xEventGroupWaitBits(
        s_evt, DISPLAY_EVT_TASK_EXITED, pdTRUE, pdFALSE, pdMS_TO_TICKS(3000)
    );
    s_task_handle = NULL;

    if ((bits & DISPLAY_EVT_TASK_EXITED) == 0) return ESP_ERR_TIMEOUT;

    display_hw_deinit();
    return ESP_OK;
}

#else
esp_err_t display_init(void) { return ESP_OK; }
esp_err_t display_deinit(void) { return ESP_OK; }
#endif