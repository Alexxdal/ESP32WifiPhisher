/*
 * esp_wifi_usb.c - Implementation of the esp_wifi-style public API
 */
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include "esp_wifi_usb.h"
#include "esp_wifi_usb_internal.h"
#include "rtl8188e_driver.h"
#include "rtl8188e_usb.h"
#include "rtl8188e_phy.h"
#include "rtl8188e_hal.h"
#include "rtl8188e_iqk.h"
#include "rtl8188e_rx.h"
#include "rtl8188e_reg.h"

static const char *TAG = "ESP_WIFI_USB";

/* ---- Shared state with rtl8188e_rx.c (extern in esp_wifi_usb_internal.h) ---- */
volatile bool              g_wifi_usb_promisc_en        = false;
wifi_usb_promiscuous_cb_t  g_wifi_usb_promisc_cb        = NULL;
volatile uint8_t           g_wifi_usb_channel           = 1;
TaskHandle_t               g_wifi_usb_rx_task_hdl       = NULL;
volatile bool              g_wifi_usb_rx_task_should_run = false;

/* ---- Globals from rtl8188e_driver.h ---- */
usb_host_client_handle_t global_client_hdl;
usb_device_handle_t      global_dev_hdl  = NULL;
TaskHandle_t             driver_task_hdl = NULL;

/* ---- Internal state ---- */
static bool              s_usb_host_installed = false;
static bool              s_chip_ready         = false;
static SemaphoreHandle_t s_bringup_done_sem   = NULL;

/* Default static transmission values */
static wifi_usb_phy_rate_t s_tx_rate      = WIFI_USB_RATE_1M;
static uint8_t             s_tx_power_idx = 0;

/**
 * @brief Pump USB host client events
 */
static void client_events_task(void *arg)
{
    while (1) {
        usb_host_client_handle_events(global_client_hdl, portMAX_DELAY);
    }
}

/**
 * @brief USB host stack background task
 */
static void host_lib_task(void *arg)
{
    while (1) {
        uint32_t event_flags;
        usb_host_lib_handle_events(portMAX_DELAY, &event_flags);
        if (event_flags & USB_HOST_LIB_EVENT_FLAGS_NO_CLIENTS) {
            ESP_LOGW(TAG, "No registered USB clients");
        }
    }
}

/**
 * @brief Client event callback (device connect/disconnect)
 */
static void client_event_cb(const usb_host_client_event_msg_t *msg, void *arg)
{
    if (msg->event == USB_HOST_CLIENT_EVENT_NEW_DEV) {
        esp_err_t err = usb_host_device_open(global_client_hdl, msg->new_dev.address, &global_dev_hdl);
        if (err == ESP_OK) {
            const usb_device_desc_t *dev_desc;
            usb_host_get_device_descriptor(global_dev_hdl, &dev_desc);
            if (dev_desc->idVendor == VID_REALTEK && dev_desc->idProduct == PID_RTL8188EU) {
                ESP_LOGI(TAG, "RTL8188EU detected (USB address %d)", msg->new_dev.address);
                xTaskNotifyGive(driver_task_hdl);
            }
        }
    } else if (msg->event == USB_HOST_CLIENT_EVENT_DEV_GONE) {
        ESP_LOGW(TAG, "Device disconnected");
        s_chip_ready = false;
    }
}

/**
 * @brief Bringup task: brings the chip from "just connected" to "radio listening"
 */
static void bringup_task(void *arg)
{
    ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
    ESP_LOGD(TAG, "Configuring chip...");

    if (usb_host_interface_claim(global_client_hdl, global_dev_hdl, 0, 0) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to claim USB interface!");
        vTaskDelete(NULL);
    }

    {
        const usb_config_desc_t *cfg;
        if (usb_host_get_active_config_descriptor(global_dev_hdl, &cfg) == ESP_OK) {
            const uint8_t *p = (const uint8_t *)cfg;
            int off = 0;
            ESP_LOGI(TAG, "Real USB endpoints for this device:");
            while (off + 2 <= cfg->wTotalLength) {
                uint8_t len  = p[off];
                uint8_t type = p[off + 1];
                if (len == 0) break;
                if (type == 0x05 && off + 6 <= cfg->wTotalLength) {
                    uint8_t  addr    = p[off + 2];
                    uint8_t  attr    = p[off + 3];
                    uint16_t maxpkt  = p[off + 4] | ((uint16_t)p[off + 5] << 8);
                    ESP_LOGI(TAG, "  addr=0x%02X (%s %s) attr=0x%02X maxpkt=%u",
                             addr, (addr & 0x80) ? "IN " : "OUT",
                             ((attr & 0x03) == 0x02) ? "bulk" : "other",
                             attr, (unsigned)maxpkt);
                }
                off += len;
            }
        } else {
            ESP_LOGW(TAG, "Failed to read config descriptor for endpoint diagnostics");
        }
    }

    /* 1. Power on, reserve queue pages and load firmware */
    rtl8188e_power_on(global_dev_hdl);
    rtl8188e_init_queue_reserved_page(global_dev_hdl);
    if (rtl8188e_load_firmware(global_dev_hdl) != ESP_OK) {
        ESP_LOGE(TAG, "Firmware load failed, stopping here.");
        vTaskDelete(NULL);
    }
    rtl8188e_start_firmware(global_dev_hdl);

    /* 2. MAC */
    rtl8188e_init_mac(global_dev_hdl);

    /* 3. Baseband and RF */
    rtl8188e_enable_bb_rf(global_dev_hdl);
    rtl8188e_init_bb_rf(global_dev_hdl);
    rtl8188e_init_rf(global_dev_hdl);

    /* 3b. Set TX buffer boundaries and build LLT */
    rtl8188e_init_trx_buffer(global_dev_hdl);

    /* 4. Tune to default channel, then calibrate */
    g_wifi_usb_channel = 1;
    rtl8188e_set_channel(global_dev_hdl, g_wifi_usb_channel);
    rtl8188e_lc_calibrate(global_dev_hdl);
    rtl8188e_iq_calibrate(global_dev_hdl);

    /* 5. Enable MAC and DMA */
    rtl8188e_start_radio(global_dev_hdl);

    /* Set hardware promiscuous mode */
    rtl_write32(global_dev_hdl, REG_RCR, RCR_REAL_CAPTURED_VALUE);
    rtl_write16(global_dev_hdl, 0x06A0, 0xFFFF);   // RXFLTMAP0 (management)
    rtl_write16(global_dev_hdl, 0x06A2, 0xFFFF);   // RXFLTMAP1 (control)
    rtl_write16(global_dev_hdl, 0x06A4, 0xFFFF);   // RXFLTMAP2 (data)

    s_chip_ready = true;
    ESP_LOGI(TAG, "Chip ready (Firmware loaded, PHY/RF calibrated, channel %u)", (unsigned)g_wifi_usb_channel);
    xSemaphoreGive(s_bringup_done_sem);

    vTaskDelete(NULL);
}

esp_err_t esp_wifi_usb_init(uint32_t timeout_ms)
{
    if (s_chip_ready) return ESP_OK;

    if (!s_usb_host_installed) {
        s_bringup_done_sem = xSemaphoreCreateBinary();

        const usb_host_config_t host_config = {
            .skip_phy_setup = false,
            .intr_flags = ESP_INTR_FLAG_LEVEL1,
        };
        esp_err_t err = usb_host_install(&host_config);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "usb_host_install failed: %d", err);
            return err;
        }

        xTaskCreate(host_lib_task, "usb_host", 4096, NULL, 5, NULL);
        xTaskCreate(bringup_task, "rtl_bringup", 4096, NULL, 4, &driver_task_hdl);

        usb_host_client_config_t client_config = {
            .is_synchronous = false,
            .max_num_event_msg = 5,
            .async = {
                .client_event_callback = client_event_cb,
                .callback_arg = NULL,
            }
        };
        err = usb_host_client_register(&client_config, &global_client_hdl);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "usb_host_client_register failed: %d", err);
            return err;
        }

        xTaskCreate(client_events_task, "usb_client_ev", 4096, NULL, 5, NULL);

        s_usb_host_installed = true;
    }

    TickType_t wait = (timeout_ms == 0) ? portMAX_DELAY : pdMS_TO_TICKS(timeout_ms);
    if (xSemaphoreTake(s_bringup_done_sem, wait) != pdTRUE) {
        ESP_LOGW(TAG, "Timeout: chip not ready within %u ms (continuing to wait in background)", (unsigned)timeout_ms);
        return ESP_ERR_TIMEOUT;
    }

    return ESP_OK;
}

esp_err_t esp_wifi_usb_deinit(void)
{
    esp_wifi_usb_stop();
    ESP_LOGW(TAG, "esp_wifi_usb_deinit: Full USB host stack unmount not implemented. RX task stopped.");
    return ESP_OK;
}

esp_err_t esp_wifi_usb_start(void)
{
    if (!s_chip_ready) return ESP_ERR_INVALID_STATE;
    if (g_wifi_usb_rx_task_hdl != NULL) return ESP_OK;

    g_wifi_usb_rx_task_should_run = true;
    BaseType_t ok = xTaskCreate(rtl8188_rx_task, "rx_task", 4096, NULL, 5, &g_wifi_usb_rx_task_hdl);
    if (ok != pdPASS) {
        g_wifi_usb_rx_task_should_run = false;
        return ESP_ERR_NO_MEM;
    }
    ESP_LOGI(TAG, "Initialized RTL8188U wifi dongle");
    return ESP_OK;
}

esp_err_t esp_wifi_usb_stop(void)
{
    if (g_wifi_usb_rx_task_hdl == NULL) return ESP_OK;

    g_wifi_usb_rx_task_should_run = false;

    for (int i = 0; i < 30 && g_wifi_usb_rx_task_hdl != NULL; i++) {
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    if (g_wifi_usb_rx_task_hdl != NULL) {
        ESP_LOGW(TAG, "RX task did not stop in time, forcing deletion");
        vTaskDelete(g_wifi_usb_rx_task_hdl);
        g_wifi_usb_rx_task_hdl = NULL;
    }
    return ESP_OK;
}

esp_err_t esp_wifi_usb_set_promiscuous(bool en)
{
    g_wifi_usb_promisc_en = en;
    ESP_LOGI(TAG, "Promiscuous mode: %s", en ? "ON" : "OFF");
    return ESP_OK;
}

esp_err_t esp_wifi_usb_get_promiscuous(bool *en)
{
    if (en == NULL) return ESP_ERR_INVALID_ARG;
    *en = g_wifi_usb_promisc_en;
    return ESP_OK;
}

esp_err_t esp_wifi_usb_set_promiscuous_rx_cb(wifi_usb_promiscuous_cb_t cb)
{
    g_wifi_usb_promisc_cb = cb;
    return ESP_OK;
}

esp_err_t esp_wifi_usb_set_channel(uint8_t primary)
{
    if (!s_chip_ready) return ESP_ERR_INVALID_STATE;
    if (primary < 1 || primary > 14) return ESP_ERR_INVALID_ARG;

    if (primary == g_wifi_usb_channel) return ESP_ERR_INVALID_STATE;

    rtl8188e_set_channel(global_dev_hdl, primary);
    rtl8188e_lc_calibrate(global_dev_hdl);
    rtl8188e_iq_calibrate(global_dev_hdl);
    g_wifi_usb_channel = primary;

    ESP_LOGI(TAG, "Channel set to %u", (unsigned)primary);
    return ESP_OK;
}

esp_err_t esp_wifi_usb_get_channel(uint8_t *primary)
{
    if (primary == NULL) return ESP_ERR_INVALID_ARG;
    *primary = g_wifi_usb_channel;
    return ESP_OK;
}

esp_err_t esp_wifi_usb_get_mac(uint8_t mac[6])
{
    if (mac == NULL) return ESP_ERR_INVALID_ARG;
    if (!s_chip_ready) return ESP_ERR_INVALID_STATE;

    for (int i = 0; i < 6; i++) {
        mac[i] = rtl_read8(global_dev_hdl, REG_MACID + i);
    }
    return ESP_OK;
}

esp_err_t esp_wifi_usb_set_mac(const uint8_t mac[6])
{
    if (mac == NULL) return ESP_ERR_INVALID_ARG;
    if (!s_chip_ready) return ESP_ERR_INVALID_STATE;

    for (int i = 0; i < 6; i++) {
        rtl_write8(global_dev_hdl, REG_MACID + i, mac[i]);
    }
    ESP_LOGI(TAG, "MAC set to %02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return ESP_OK;
}

esp_err_t esp_wifi_usb_set_rate(wifi_usb_phy_rate_t rate)
{
    if (rate > WIFI_USB_RATE_MCS7) return ESP_ERR_INVALID_ARG;
    s_tx_rate = rate;
    ESP_LOGI(TAG, "Fixed TX rate set to index 0x%02X", (unsigned)rate);
    return ESP_OK;
}

esp_err_t esp_wifi_usb_get_rate(wifi_usb_phy_rate_t *rate)
{
    if (rate == NULL) return ESP_ERR_INVALID_ARG;
    *rate = s_tx_rate;
    return ESP_OK;
}

esp_err_t esp_wifi_usb_set_tx_power(uint8_t power_index)
{
    if (!s_chip_ready) return ESP_ERR_INVALID_STATE;
    if (power_index > 63) return ESP_ERR_INVALID_ARG;

    uint32_t val = ((uint32_t)power_index << 24) | ((uint32_t)power_index << 16) |
                   ((uint32_t)power_index << 8)  |  (uint32_t)power_index;

    rtl_write32(global_dev_hdl, REG_TX_AGC_A_RATE18_06,   val);
    rtl_write32(global_dev_hdl, REG_TX_AGC_A_RATE54_24,   val);
    rtl_write32(global_dev_hdl, REG_TX_AGC_A_MCS03_MCS00, val);
    rtl_write32(global_dev_hdl, REG_TX_AGC_A_MCS07_MCS04, val);
    rtl_write32(global_dev_hdl, REG_TX_AGC_A_MCS11_MCS08, val);
    rtl_write32(global_dev_hdl, REG_TX_AGC_A_MCS15_MCS12, val);

    /* CCK rates live in single bytes, not full dwords: byte[1] of
     * REG_TX_AGC_A_CCK1_MCS32 is CCK-1M, bytes[1:3] of
     * REG_TX_AGC_B_CCK11_A_CCK2_11 are CCK-2/5.5/11M. */
    rtl_write8(global_dev_hdl, REG_TX_AGC_A_CCK1_MCS32 + 1,      power_index);
    rtl_write8(global_dev_hdl, REG_TX_AGC_B_CCK11_A_CCK2_11 + 1, power_index);
    rtl_write8(global_dev_hdl, REG_TX_AGC_B_CCK11_A_CCK2_11 + 2, power_index);
    rtl_write8(global_dev_hdl, REG_TX_AGC_B_CCK11_A_CCK2_11 + 3, power_index);

    s_tx_power_idx = power_index;
    ESP_LOGI(TAG, "TX power index set to %u/63", power_index);
    return ESP_OK;
}

esp_err_t esp_wifi_usb_get_tx_power(uint8_t *power_index)
{
    if (power_index == NULL) return ESP_ERR_INVALID_ARG;
    *power_index = s_tx_power_idx;
    return ESP_OK;
}

/* dBm <-> hardware index conversion, plus a per-board offset that
 * compensates for the missing EFUSE TSSI calibration data. */
static float s_tx_power_cal_offset_dbm = 0.0f;

esp_err_t esp_wifi_usb_set_tx_power_dbm(float dbm)
{
    float idx_f = (dbm - s_tx_power_cal_offset_dbm) * RTL8188E_TXGI_PER_DBM;
    if (idx_f < 0.0f) idx_f = 0.0f;
    if (idx_f > RTL8188E_TXGI_MAX) idx_f = RTL8188E_TXGI_MAX;
    return esp_wifi_usb_set_tx_power((uint8_t)(idx_f + 0.5f));
}

esp_err_t esp_wifi_usb_get_tx_power_dbm(float *dbm)
{
    if (dbm == NULL) return ESP_ERR_INVALID_ARG;
    *dbm = ((float)s_tx_power_idx / RTL8188E_TXGI_PER_DBM) + s_tx_power_cal_offset_dbm;
    return ESP_OK;
}

esp_err_t esp_wifi_usb_set_tx_power_calibration_offset(float offset_dbm)
{
    s_tx_power_cal_offset_dbm = offset_dbm;
    return ESP_OK;
}

esp_err_t esp_wifi_usb_get_tx_power_calibration_offset(float *offset_dbm)
{
    if (offset_dbm == NULL) return ESP_ERR_INVALID_ARG;
    *offset_dbm = s_tx_power_cal_offset_dbm;
    return ESP_OK;
}

/* ------------------------------------------------------------------ *
 *  RX hardware filters
 * ------------------------------------------------------------------ */

static uint32_t s_promisc_filter_mask      = WIFI_PROMIS_FILTER_MASK_ALL;
static uint32_t s_promisc_ctrl_filter_mask = WIFI_PROMIS_CTRL_FILTER_MASK_ALL;

/**
 * @brief Applies the mgmt/ctrl/data/fcsfail filter to REG_RXFLTMAP0/1/2 and RCR_ACRC32
 */
esp_err_t esp_wifi_usb_set_promiscuous_filter(const wifi_promiscuous_filter_t *filter)
{
    if (filter == NULL) return ESP_ERR_INVALID_ARG;
    if (!s_chip_ready) return ESP_ERR_INVALID_STATE;

    uint32_t mask = filter->filter_mask;

    rtl_write16(global_dev_hdl, REG_RXFLTMAP0, (mask & WIFI_PROMIS_FILTER_MASK_MGMT) ? 0xFFFF : 0x0000);
    rtl_write16(global_dev_hdl, REG_RXFLTMAP1, (mask & WIFI_PROMIS_FILTER_MASK_CTRL) ? 0xFFFF : 0x0000);
    rtl_write16(global_dev_hdl, REG_RXFLTMAP2, (mask & WIFI_PROMIS_FILTER_MASK_DATA) ? 0xFFFF : 0x0000);

    uint32_t rcr = rtl_read32(global_dev_hdl, REG_RCR);
    if (mask & WIFI_PROMIS_FILTER_MASK_FCSFAIL) rcr |= RCR_ACRC32;
    else                                        rcr &= ~RCR_ACRC32;
    rtl_write32(global_dev_hdl, REG_RCR, rcr);

    s_promisc_filter_mask = mask;
    ESP_LOGI(TAG, "Promiscuous filter mask set to 0x%08" PRIX32, mask);
    return ESP_OK;
}

esp_err_t esp_wifi_usb_get_promiscuous_filter(wifi_promiscuous_filter_t *filter)
{
    if (filter == NULL) return ESP_ERR_INVALID_ARG;
    filter->filter_mask = s_promisc_filter_mask;
    return ESP_OK;
}

/**
 * @brief Applies the control-subtype filter to REG_RXFLTMAP1
 */
esp_err_t esp_wifi_usb_set_promiscuous_ctrl_filter(const wifi_promiscuous_filter_t *filter)
{
    if (filter == NULL) return ESP_ERR_INVALID_ARG;
    if (!s_chip_ready) return ESP_ERR_INVALID_STATE;

    uint32_t mask = filter->filter_mask;
    uint16_t rxfltmap1 = 0;

    /* WIFI_PROMIS_CTRL_FILTER_MASK_* bit N (N=23..31) maps to control
     * subtype (N-16) (7..15) in REG_RXFLTMAP1's per-subtype bitmap. */
    for (int bit = 23; bit <= 31; bit++) {
        if (mask & (1u << bit)) {
            rxfltmap1 |= (uint16_t)(1u << (bit - 16));
        }
    }
    rtl_write16(global_dev_hdl, REG_RXFLTMAP1, rxfltmap1);

    s_promisc_ctrl_filter_mask = mask;
    ESP_LOGI(TAG, "Promiscuous ctrl filter mask set to 0x%08" PRIX32, mask);
    return ESP_OK;
}

esp_err_t esp_wifi_usb_get_promiscuous_ctrl_filter(wifi_promiscuous_filter_t *filter)
{
    if (filter == NULL) return ESP_ERR_INVALID_ARG;
    filter->filter_mask = s_promisc_ctrl_filter_mask;
    return ESP_OK;
}

/* ------------------------------------------------------------------ *
 *  Raw Transmission
 * ------------------------------------------------------------------ */

#define TX_DESC_LEN 48
static const uint8_t s_tx_desc_template[TX_DESC_LEN] = {
    0x58, 0x00, 0x20, 0x8D,  0x01, 0x12, 0x00, 0x08,
    0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x80,
    0x00, 0x05, 0x00, 0x00,  0x00, 0x1F, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
};

static void bulk_out_cb(usb_transfer_t *transfer)
{
    SemaphoreHandle_t sem = (SemaphoreHandle_t)transfer->context;
    xSemaphoreGive(sem);
}

/**
 * @brief Calculate and write the mandatory TX descriptor checksum
 */
static void rtl_tx_desc_checksum(uint8_t *desc32)
{
    desc32[28] = 0;
    desc32[29] = 0;

    uint16_t chk = 0;
    for (int i = 0; i < 16; i++) {
        uint16_t word = (uint16_t)desc32[2 * i] | ((uint16_t)desc32[2 * i + 1] << 8);
        chk ^= word;
    }

    desc32[28] = (uint8_t)(chk & 0xFF);
    desc32[29] = (uint8_t)((chk >> 8) & 0xFF);
}

/**
 * @brief Reads an entry from the Link List Table (LLT)
 */
static bool rtl_llt_read(usb_device_handle_t dev, uint8_t address, uint8_t *out)
{
    uint32_t value = _LLT_INIT_ADDR(address) | _LLT_OP(_LLT_READ_ACCESS);
    rtl_write32(dev, REG_LLT_INIT, value);

    for (int count = POLLING_LLT_THRESHOLD; count > 0; count--) {
        value = rtl_read32(dev, REG_LLT_INIT);
        if (_LLT_OP_VALUE(value) == _LLT_NO_ACTIVE) {
            *out = (uint8_t)(value & 0xFF);
            return true;
        }
    }
    return false;
}

/**
 * @brief Reads 8 bytes from the packet buffer via the debug window
 */
static bool rtl_pktbuf_read8(usb_device_handle_t dev, uint16_t flag_reg, uint16_t addr8,
                             uint32_t *lo, uint32_t *hi)
{
    rtl_write16(dev, REG_PKTBUF_DBG_ADDR, addr8);
    rtl_write8(dev, flag_reg, 0);

    for (int count = 20; count > 0; count--) {
        if (rtl_read8(dev, flag_reg) != 0) {
            *lo = rtl_read32(dev, REG_PKTBUF_DBG_DATA_L);
            *hi = rtl_read32(dev, REG_PKTBUF_DBG_DATA_H);
            return true;
        }
    }
    return false;
}

/**
 * @brief Performs a deep probe of the TX path (runs only once after first transmission)
 */
static void rtl_tx_deep_probe(usb_device_handle_t dev, uint32_t expect_dw0)
{
    ESP_LOGD(TAG, "PROBE 1/4 Config Buffer: PBP=0x%02X PKT_BUFF_ACCESS_CTRL=0x%02X TRXFF_BNDY=0x%08X TRXFF_STATUS=0x%08X RQPN=0x%08X RQPN_NPQ=0x%02X",
             rtl_read8(dev, REG_PBP),
             rtl_read8(dev, REG_PKT_BUFF_ACCESS_CTRL),
             (unsigned int)rtl_read32(dev, REG_TRXFF_BNDY),
             (unsigned int)rtl_read32(dev, REG_TRXFF_STATUS),
             (unsigned int)rtl_read32(dev, REG_RQPN),
             rtl_read8(dev, REG_RQPN_NPQ));

    static const struct { uint8_t addr; uint8_t expect; } llt_check[] = {
        { 0x00, 0x01 },
        { 0x01, 0x02 },
        { 0xA8, 0xA9 },
        { 0xA9, 0xFF },
        { 0xAA, 0xAB },
        { 0xAF, 0xAA },
    };
    char llt_line[192];
    int  llt_pos = 0;
    int  llt_bad = 0;
    for (unsigned k = 0; k < sizeof(llt_check) / sizeof(llt_check[0]); k++) {
        uint8_t got = 0;
        bool ok = rtl_llt_read(dev, llt_check[k].addr, &got);
        if (!ok || got != llt_check[k].expect)
            llt_bad++;
        llt_pos += snprintf(llt_line + llt_pos, sizeof(llt_line) - llt_pos,
                            "[%02X]=%s%02X/exp.%02X ",
                            llt_check[k].addr, ok ? "" : "TIMEOUT:",
                            got, llt_check[k].expect);
        if (llt_pos >= (int)sizeof(llt_line) - 24)
            break;
    }
    ESP_LOGD(TAG, "PROBE 2/4 LLT readback: %s -> %s", llt_line,
             llt_bad == 0 ? "matches bring-up state"
                          : "differs from bring-up (normal if traffic has passed)");

    uint8_t access_prev = rtl_read8(dev, REG_PKT_BUFF_ACCESS_CTRL);

    rtl_write8(dev, REG_PKT_BUFF_ACCESS_CTRL, RXPKT_BUF_SELECT);
    char rx_line[128];
    int  rx_pos = 0;
    for (uint16_t u = 0; u < 4; u++) {
        uint32_t lo = 0, hi = 0;
        if (!rtl_pktbuf_read8(dev, REG_RXPKTBUF_DBG, u, &lo, &hi)) {
            rx_pos += snprintf(rx_line + rx_pos, sizeof(rx_line) - rx_pos, "TIMEOUT ");
            continue;
        }
        rx_pos += snprintf(rx_line + rx_pos, sizeof(rx_line) - rx_pos,
                           "%08X %08X ", (unsigned int)lo, (unsigned int)hi);
    }
    ESP_LOGD(TAG, "PROBE 3/4 RX Buffer (first 32 bytes): %s", rx_line);

    rtl_write8(dev, REG_PKT_BUFF_ACCESS_CTRL, TXPKT_BUF_SELECT);

    int      found_at = -1;
    int      timeouts = 0;
    char     tx_line[160];
    int      tx_pos = 0;
    for (uint16_t u = 0; u < 256; u++) {
        uint32_t lo = 0, hi = 0;
        if (!rtl_pktbuf_read8(dev, REG_TXPKTBUF_DBG, u, &lo, &hi)) {
            timeouts++;
            continue;
        }
        if ((u % 16) < 2 && u < 64 && tx_pos < (int)sizeof(tx_line) - 24) {
            tx_pos += snprintf(tx_line + tx_pos, sizeof(tx_line) - tx_pos,
                               "%s%08X %08X", (u % 16) == 0 ? "| " : " ",
                               (unsigned int)lo, (unsigned int)hi);
        }
        if (lo == expect_dw0 && found_at < 0)
            found_at = u * 8;
    }

    rtl_write8(dev, REG_PKT_BUFF_ACCESS_CTRL, access_prev);

    ESP_LOGD(TAG, "PROBE 4/4 TX Buffer Pages 0-3: %s", tx_line);
    if (found_at >= 0) {
        ESP_LOGD(TAG, "PROBE 4/4 Result: DWORD0 0x%08X FOUND at offset %d (Bulk-OUT bytes arrive, issue is downstream)",
                 (unsigned int)expect_dw0, found_at);
    } else {
        ESP_LOGD(TAG, "PROBE 4/4 Result: DWORD0 0x%08X NOT FOUND in first 2KB (timeouts: %d) (DMA takes packet but fails to deposit)",
                 (unsigned int)expect_dw0, timeouts);
    }
}

#define QSLT_BE       0x00
#define QSLT_BK       0x02
#define QSLT_VI       0x05
#define QSLT_VO       0x07
#define QSLT_BEACON   0x10
#define QSLT_MGNT     0x12

/**
 * @brief Maps HW queue to USB Bulk-Out endpoint
 */
static uint8_t qsel_to_bulk_out_ep(uint8_t qsel)
{
    switch (qsel) {
    case QSLT_MGNT:
    case QSLT_VI:
    case QSLT_VO:
    case QSLT_BEACON:
        return 0x02;
    case QSLT_BE:
    case QSLT_BK:
    default:
        return 0x03;
    }
}

static uint8_t tid_to_qsel(uint8_t tid)
{
    static const uint8_t map[8] = {
        QSLT_BE, QSLT_BK, QSLT_BK, QSLT_BE, QSLT_VI, QSLT_VI, QSLT_VO, QSLT_VO
    };
    return map[tid & 0x07];
}

/**
 * @brief Classifies the frame to determine QSEL and BMC bit
 */
static void classify_frame(const uint8_t *frame, int len, uint8_t *qsel_out, bool *bmc_out,
                           uint8_t *type_out, bool *qos_out)
{
    uint8_t fc0     = frame[0];
    uint8_t type    = (fc0 >> 2) & 0x3;
    uint8_t subtype = (fc0 >> 4) & 0xF;

    *bmc_out  = (len >= 10) ? ((frame[4] & 0x01) != 0) : true;
    *type_out = type;
    *qos_out  = (type == 2) && ((subtype & 0x08) != 0);

    if (type == 0) {
        *qsel_out = QSLT_MGNT;
    } else if (type == 2) {
        if (*qos_out && len >= 26) {
            uint8_t tid = frame[24] & 0x0F;
            *qsel_out = tid_to_qsel(tid);
        } else {
            *qsel_out = QSLT_BE;
        }
    } else {
        *qsel_out = QSLT_MGNT;
    }
}

esp_err_t esp_wifi_usb_80211_tx(const void *buffer, int len, bool en_sys_seq)
{
    (void)en_sys_seq;

    if (!s_chip_ready) return ESP_ERR_INVALID_STATE;
    if (buffer == NULL || len <= 0 || len > 2304) return ESP_ERR_INVALID_ARG;

    int pkt_offset_units = ((32 + len) % 64) == 0 ? 1 : 0;
    int header_len = 32 + 8 * pkt_offset_units;
    int total_len  = header_len + len;

    usb_transfer_t *transfer;
    esp_err_t err = usb_host_transfer_alloc(total_len, 0, &transfer);
    if (err != ESP_OK) return err;

    memset(transfer->data_buffer, 0, header_len);
    memcpy(transfer->data_buffer, s_tx_desc_template, 32);

    transfer->data_buffer[7] = (uint8_t)((transfer->data_buffer[7] & ~0x7C)
                                         | ((pkt_offset_units << 2) & 0x7C));

    transfer->data_buffer[0] = (uint8_t)(len & 0xFF);
    transfer->data_buffer[1] = (uint8_t)((len >> 8) & 0xFF);

    uint8_t qsel;
    bool    bmc;
    uint8_t frame_type;
    bool    is_qos;
    classify_frame((const uint8_t *)buffer, len, &qsel, &bmc, &frame_type, &is_qos);

    transfer->data_buffer[5] = (transfer->data_buffer[5] & ~0x1F) | (qsel & 0x1F);
    transfer->data_buffer[17] |= (1 << 0) | (1 << 2);
    if (bmc) {
        transfer->data_buffer[3] |= 0x01;
    } else {
        transfer->data_buffer[3] &= ~0x01;
    }

    transfer->data_buffer[20] = (transfer->data_buffer[20] & ~0x3F) | ((uint8_t)s_tx_rate & 0x3F);

    if (is_qos) {
        transfer->data_buffer[15] &= ~0x80;
        transfer->data_buffer[16] |= 0x40;
    } else {
        transfer->data_buffer[15] |= 0x80;
        transfer->data_buffer[16] |= 0x80;
    }
    transfer->data_buffer[10] |= 0x01;
    transfer->data_buffer[10] |= 0x08;

    if (frame_type == 0) {
        transfer->data_buffer[22] |= 0x32;
    }

    rtl_tx_desc_checksum(transfer->data_buffer);

    memcpy(transfer->data_buffer + header_len, buffer, len);

    uint16_t desc_chk = (uint16_t)transfer->data_buffer[28] | ((uint16_t)transfer->data_buffer[29] << 8);
    ESP_LOGD(TAG, "TX diag: QSEL=0x%02X RATE=0x%02X BMC=%d len=%d PKT_OFF=%d hdr=%d tot=%d CHKSUM=0x%04X | TXPAUSE=0x%02X CR=0x%04X RQPN=0x%08X",
             qsel, (unsigned)s_tx_rate, bmc, len,
             pkt_offset_units, header_len, total_len, desc_chk,
             rtl_read8(global_dev_hdl, REG_TXPAUSE),
             rtl_read16(global_dev_hdl, REG_CR),
             rtl_read32(global_dev_hdl, REG_RQPN));

    uint32_t dbg_txdma_pre    = rtl_read32(global_dev_hdl, REG_TXDMA_STATUS);
    uint16_t dbg_pktempty_pre = rtl_read16(global_dev_hdl, REG_TXPKT_EMPTY);
    uint8_t  dbg_fmethr       = rtl_read8(global_dev_hdl, REG_FMETHR);
    uint32_t dbg_fwdl         = rtl_read32(global_dev_hdl, REG_MCUFWDL);
    uint32_t dbg_offchk = rtl_read32(global_dev_hdl, REG_TXDMA_OFFSET_CHK);
    uint32_t dbg_fifopage = rtl_read32(global_dev_hdl, REG_FIFOPAGE);

    uint32_t dbg_txdma_cleared = dbg_txdma_pre;
    if (dbg_txdma_pre != 0 && dbg_txdma_pre != 0xEAEAEAEAu) {
        rtl_write32(global_dev_hdl, REG_TXDMA_STATUS, dbg_txdma_pre);
        dbg_txdma_cleared = rtl_read32(global_dev_hdl, REG_TXDMA_STATUS);
    }

    ESP_LOGD(TAG, "TX diag (before): TXDMA_ST=0x%08X (after W1C: 0x%08X, %s) OFFSET_CHK=0x%08X DROP_DATA_EN=%s TXPKT_EMPTY=0x%04X FMETHR=0x%02X MCUFWDL=0x%08X FW_READY=%s",
             (unsigned int)dbg_txdma_pre,
             (unsigned int)dbg_txdma_cleared,
             (dbg_txdma_cleared == 0) ? "clearable=latch bit" : "NOT clearable=permanent state",
             (unsigned int)dbg_offchk,
             (dbg_offchk & DROP_DATA_EN) ? "ON" : "OFF",
             dbg_pktempty_pre, dbg_fmethr,
             (unsigned int)dbg_fwdl,
             (dbg_fwdl & MCUFWDL_WINTINI_RDY) ? "YES" : "NO");

    {
        uint32_t rqpn = rtl_read32(global_dev_hdl, REG_RQPN);
        ESP_LOGD(TAG, "TX diag PAGES (before): alloc 0x200=0x%08X (HPQ=%u LPQ=%u PUBQ=%u) | avail 0x204=0x%08X (HPQ=%u LPQ=%u PUBQ=%u) -> %s",
                 (unsigned int)rqpn,
                 (unsigned)(rqpn & 0xFF), (unsigned)((rqpn >> 8) & 0xFF), (unsigned)((rqpn >> 16) & 0xFF),
                 (unsigned int)dbg_fifopage,
                 (unsigned)(dbg_fifopage & 0xFF), (unsigned)((dbg_fifopage >> 8) & 0xFF),
                 (unsigned)((dbg_fifopage >> 16) & 0xFF),
                 ((dbg_fifopage & 0x00FFFFFF) == (rqpn & 0x00FFFFFF))
                     ? "TX buffer empty"
                     : "something OCCUPIES pages");
    }

    SemaphoreHandle_t sem = xSemaphoreCreateBinary();
    transfer->device_handle = global_dev_hdl;
    transfer->bEndpointAddress = qsel_to_bulk_out_ep(qsel);
    transfer->num_bytes = total_len;
    transfer->callback = bulk_out_cb;
    transfer->context = sem;

    err = usb_host_transfer_submit(transfer);
    if (err == ESP_OK) {
        if (xSemaphoreTake(sem, pdMS_TO_TICKS(2000)) != pdTRUE) {
            ESP_LOGE(TAG, "Frame sending timeout (Bulk OUT)");
            err = ESP_ERR_TIMEOUT;
        } else if (transfer->status != USB_TRANSFER_STATUS_COMPLETED) {
            ESP_LOGE(TAG, "Frame sending failed: status=%d", transfer->status);
            err = ESP_FAIL;
        } else if (transfer->actual_num_bytes != total_len) {
            ESP_LOGE(TAG, "Frame sending TRUNCATED: requested %d bytes, confirmed %d",
                     total_len, (int)transfer->actual_num_bytes);
            err = ESP_FAIL;
        }
    }

    ESP_LOGD(TAG, "TX diag (after): status=%d TXPAUSE=0x%02X RQPN=0x%08X",
             transfer->status,
             rtl_read8(global_dev_hdl, REG_TXPAUSE),
             rtl_read32(global_dev_hdl, REG_RQPN));

    uint32_t dbg_txdma_post    = rtl_read32(global_dev_hdl, REG_TXDMA_STATUS);
    uint16_t dbg_pktempty_post = rtl_read16(global_dev_hdl, REG_TXPKT_EMPTY);
    vTaskDelay(pdMS_TO_TICKS(20));
    uint16_t dbg_pktempty_late = rtl_read16(global_dev_hdl, REG_TXPKT_EMPTY);
    uint32_t dbg_fifopage_post = rtl_read32(global_dev_hdl, REG_FIFOPAGE);
    ESP_LOGD(TAG, "TX diag PAGES (after): avail 0x204 0x%08X -> 0x%08X %s",
             (unsigned int)dbg_fifopage, (unsigned int)dbg_fifopage_post,
             (dbg_fifopage_post != dbg_fifopage)
                 ? "CHANGED: pages allocated and not yet freed"
                 : "(unchanged)");

    ESP_LOGD(TAG, "TX diag (after): TXDMA_ST=0x%08X TXPKT_EMPTY %04X->%04X->%04X %s",
             (unsigned int)dbg_txdma_post,
             dbg_pktempty_pre, dbg_pktempty_post, dbg_pktempty_late,
             (dbg_pktempty_pre == dbg_pktempty_post && dbg_pktempty_pre == dbg_pktempty_late)
                 ? "(unchanged)"
                 : ((dbg_pktempty_post != dbg_pktempty_late)
                        ? "(queue drained: MAC consumed packet)"
                        : "ENTERED BUT STUCK: MAC not extracting"));

    static bool deep_probe_done = false;
    if (!deep_probe_done) {
        deep_probe_done = true;
        uint32_t expect_dw0 = (uint32_t)transfer->data_buffer[0]
                            | ((uint32_t)transfer->data_buffer[1] << 8)
                            | ((uint32_t)transfer->data_buffer[2] << 16)
                            | ((uint32_t)transfer->data_buffer[3] << 24);
        rtl_tx_deep_probe(global_dev_hdl, expect_dw0);
    }

    static bool rearm_done = false;
    if (!rearm_done) {
        rearm_done = true;

        rtl_write8(global_dev_hdl, REG_RQPN_NPQ, RQPN_NPQ_8188E);
        rtl_write32(global_dev_hdl, REG_RQPN,
                    (1u << 31) |
                    ((uint32_t)RQPN_PUBQ_8188E << 16) |
                    ((uint32_t)RQPN_LPQ_8188E  << 8)  |
                     (uint32_t)RQPN_HPQ_8188E);
        rtl_write8(global_dev_hdl, REG_TXPKTBUF_BCNQ_BDNY,      TX_PAGE_BOUNDARY_8188E);
        rtl_write8(global_dev_hdl, REG_TXPKTBUF_MGQ_BDNY,       TX_PAGE_BOUNDARY_8188E);
        rtl_write8(global_dev_hdl, REG_TXPKTBUF_WMAC_LBK_BF_HD, TX_PAGE_BOUNDARY_8188E);
        rtl_write8(global_dev_hdl, REG_TRXFF_BNDY,              TX_PAGE_BOUNDARY_8188E);
        rtl_write8(global_dev_hdl, REG_TDECTRL + 1,             TX_PAGE_BOUNDARY_8188E);

        uint16_t pe_before = rtl_read16(global_dev_hdl, REG_TXPKT_EMPTY);
        uint16_t pe_after  = pe_before;

        transfer->num_bytes        = total_len;
        transfer->bEndpointAddress = qsel_to_bulk_out_ep(qsel);
        esp_err_t err_r = usb_host_transfer_submit(transfer);
        if (err_r == ESP_OK && xSemaphoreTake(sem, pdMS_TO_TICKS(2000)) == pdTRUE) {
            vTaskDelay(pdMS_TO_TICKS(2));
            pe_after = rtl_read16(global_dev_hdl, REG_TXPKT_EMPTY);
        }
        ESP_LOGD(TAG, "REARM PROBE: RQPN rewritten (readback 0x%08X NPQ=0x%02X) submit=%d status=%d TXPKT_EMPTY 0x%04X->0x%04X TXDMA_ST=0x%08X %s",
                 (unsigned int)rtl_read32(global_dev_hdl, REG_RQPN),
                 rtl_read8(global_dev_hdl, REG_RQPN_NPQ),
                 (int)err_r, (int)transfer->status,
                 pe_before, pe_after,
                 (unsigned int)rtl_read32(global_dev_hdl, REG_TXDMA_STATUS),
                 (pe_after != pe_before)
                     ? "ENTERED after rearm: page allocator was the issue"
                     : "(nothing: page allocator cleared)");
    }

    usb_host_transfer_free(transfer);
    vSemaphoreDelete(sem);
    return err;
}

