#if defined(CONFIG_IDF_TARGET_ESP32S2) || defined(CONFIG_IDF_TARGET_ESP32S3)

#include <string.h>
#include "rtl8188e_rx.h"
#include "rtl8188e_usb.h"
#include "rtl8188e_phy.h"
#include "esp_wifi_usb_internal.h"

static const char *TAG = "RTL8188_RX";

/* Static buffer for the promiscuous callback to avoid per-frame malloc/free 
 * and prevent task stack overflow. Valid only during the callback execution. */
#define WIFI_USB_MAX_FRAME  2400
static uint8_t s_promisc_pkt_buf[sizeof(wifi_promiscuous_pkt_t) + WIFI_USB_MAX_FRAME];

/**
 * @brief USB Bulk Transfer Callback
 */
static void bulk_transfer_cb(usb_transfer_t *transfer)
{
    SemaphoreHandle_t sync_sem = (SemaphoreHandle_t)transfer->context;
    xSemaphoreGive(sync_sem);
}

/**
 * @brief Dumps MAC/DMA RX registers for diagnostics
 */
void rtl8188_dump_rx_state(void)
{
    ESP_LOGD(TAG, "  FW : 0x0080=0x%08X  MSR(0x0102)=0x%02X",
             (unsigned int)rtl_read32(global_dev_hdl, 0x0080),
             (unsigned int)rtl_read8(global_dev_hdl, 0x0102));

    ESP_LOGD(TAG, "  MAC: CR=0x%04X RCR=0x%08X RXPKT_NUM=0x%08X RXDMA_ST=0x%02X RXFF_PTR=0x%08X",
             (unsigned int)rtl_read16(global_dev_hdl, 0x0100),
             (unsigned int)rtl_read32(global_dev_hdl, 0x0608),
             (unsigned int)rtl_read32(global_dev_hdl, 0x0284),
             (unsigned int)rtl_read8(global_dev_hdl,  0x0288),
             (unsigned int)rtl_read32(global_dev_hdl, 0x011C));

    /* Verify LSSI bus. RF_0x18 must contain the programmed channel. */
    ESP_LOGD(TAG, "  RF : 0x00=0x%05X  0x18=0x%05X (expected 0x%05X)",
             (unsigned int)rtl_read_rf(global_dev_hdl, 0x00),
             (unsigned int)rtl_read_rf(global_dev_hdl, 0x18),
             (unsigned int)(g_rf_chnlbw_val & 0xFFFFF));

    /* Freeze baseband counters before reading */
    rtl_bb_write_mask(global_dev_hdl, 0x0C00, 1u << 31, 1);
    rtl_bb_write_mask(global_dev_hdl, 0x0D00, 1u << 31, 1);

    uint32_t t1 = rtl_read32(global_dev_hdl, 0x0CF0);
    uint32_t t2 = rtl_read32(global_dev_hdl, 0x0DA0);
    uint32_t t3 = rtl_read32(global_dev_hdl, 0x0DA4);
    uint32_t a58 = rtl_read32(global_dev_hdl, 0x0A58);
    uint32_t a5c = rtl_read32(global_dev_hdl, 0x0A5C);
    uint32_t a60 = rtl_read32(global_dev_hdl, 0x0A60);

    /* Resume counters */
    rtl_bb_write_mask(global_dev_hdl, 0x0C00, 1u << 31, 0);
    rtl_bb_write_mask(global_dev_hdl, 0x0D00, 1u << 31, 0);

    unsigned int ofdm_cca = t2 & 0xFFFF;
    unsigned int cck_cca  = ((a60 & 0x00FF) << 8) | ((a60 & 0xFF00) >> 8);
    unsigned int cck_fa   = (a5c & 0xFF) | (((a58 >> 24) & 0xFF) << 8);

    ESP_LOGD(TAG, "  PHY: OFDM_CCA=%u CCK_CCA=%u | fsync_fail=%u parity=%u crc8=%u CCK_FA=%u",
             ofdm_cca, cck_cca,
             (unsigned int)(t1 & 0xFFFF), (unsigned int)(t2 >> 16),
             (unsigned int)(t3 >> 16), cck_fa);

    ESP_LOGD(TAG, "  BB : 0x800=0x%08X 0xC04=0x%08X 0xC50=0x%08X 0x870=0x%08X XTAL=0x%08X",
             (unsigned int)rtl_read32(global_dev_hdl, 0x0800),
             (unsigned int)rtl_read32(global_dev_hdl, 0x0C04),
             (unsigned int)rtl_read32(global_dev_hdl, 0x0C50),
             (unsigned int)rtl_read32(global_dev_hdl, 0x0870),
             (unsigned int)rtl_read32(global_dev_hdl, 0x0024));
}

/**
 * @brief Decodes the RSSI from the 32-byte phy status block
 */
static int8_t decode_rssi(const uint8_t *phy, bool is_cck)
{
    int rpt;

    if (is_cck) {
        uint8_t agc     = phy[5]; 
        uint8_t lna_idx = (agc & 0xE0) >> 5;
        int     vga_idx = agc & 0x1F;

        switch (lna_idx) {
            case 7:  rpt = (vga_idx <= 27) ? -100 + 2 * (27 - vga_idx) : -100; break;
            case 6:  rpt = -48 + 2 * (2  - vga_idx); break;
            case 5:  rpt = -42 + 2 * (7  - vga_idx); break;
            case 4:  rpt = -36 + 2 * (7  - vga_idx); break;
            case 3:  rpt = -24 + 2 * (7  - vga_idx); break;
            case 2:  rpt = -12 + 2 * (5  - vga_idx); break;
            case 1:  rpt =  8 - 2 * vga_idx; break;
            default: rpt = 14 - 2 * vga_idx; break;
        }
    } else {
        /* pwdb_all is half-dB scaled: bit0 is a fractional/reserved bit,
         * bit7 is reserved, the power index is bits[6:1]. */
        uint8_t pwdb_all = phy[4];
        rpt = (int)((pwdb_all >> 1) & 0x7F) - 110;
    }

    if (rpt > 0)    rpt = 0;
    if (rpt < -100) rpt = -100;
    return (int8_t)rpt;
}

/**
 * @brief Parses a single [RX descriptor][drvinfo][802.11 frame] block.
 * 
 * @return Number of consumed bytes, or 0 if block is invalid.
 */
static int rx_parse_one_block(const uint8_t *buf, int buf_len)
{
    if (buf_len < 24) return 0;

    uint32_t d0 = ((uint32_t)buf[0])       | ((uint32_t)buf[1] << 8) |
                  ((uint32_t)buf[2] << 16) | ((uint32_t)buf[3] << 24);

    uint16_t pkt_len    = d0 & 0x3FFF;
    bool     crc_err    = (d0 >> 14) & 0x1;
    bool     icv_err    = (d0 >> 15) & 0x1;
    uint8_t  drvinfo_sz = (d0 >> 16) & 0xF;   /* 8-byte units */
    uint8_t  shift      = (d0 >> 24) & 0x3;
    bool     physt      = (d0 >> 26) & 0x1;   /* PHY status block present */

    /* Handle TX/HIS reports (interleaved with standard RX frames) */
    if (buf_len >= 16) {
        uint8_t pkt_rpt_type = (buf[13] >> 6) & 0x3;

        if (pkt_rpt_type != 0) {
            if (pkt_rpt_type == 1 && buf_len >= 32) {
                const uint8_t *rpt = buf + 24;
                bool     pkt_ok        = (rpt[1] & 0x40) != 0;
                bool     bmc_rpt       = (rpt[1] & 0x80) != 0;
                uint8_t  mac_id        =  rpt[1] & 0x3F;
                uint8_t  retry_cnt     =  rpt[2] & 0x3F;
                bool     lifetime_over = (rpt[2] & 0x40) != 0;
                bool     retry_over    = (rpt[2] & 0x80) != 0;
                bool     underflow     = (rpt[0] & 0x10) != 0;
                uint8_t  final_rate    =  rpt[5];
                uint8_t  rpt_qsel      = (rpt[6] >> 4) & 0x0F;

                ESP_LOGD(TAG, "TX_REPORT1: %s retries=%u rate=0x%02X mac_id=%u bmc=%d qsel=0x%X%s%s%s | raw=%02X %02X %02X %02X %02X %02X %02X %02X",
                         pkt_ok ? "OK" : "FAILED",
                         retry_cnt, final_rate, mac_id, bmc_rpt, rpt_qsel,
                         retry_over    ? " RETRY_OVER"    : "",
                         lifetime_over ? " LIFETIME_OVER" : "",
                         underflow     ? " TXDMA_UNDERFLOW" : "",
                         rpt[0], rpt[1], rpt[2], rpt[3], rpt[4], rpt[5], rpt[6], rpt[7]);
                return 32; 
            }
            return 0; 
        }
    }

    if (pkt_len == 0) return 0; 

    int frame_off   = 24 + (drvinfo_sz * 8) + shift;
    int block_len   = frame_off + pkt_len;

    /* Hardware raw rate index */
    uint8_t rate_idx = 0;
    if (buf_len >= 16) {
        rate_idx = buf[12] & 0x3F;
    }

    if (block_len > buf_len) {
        ESP_LOGD(TAG, "Inconsistent descriptor: len=%u offset=%d avail=%d", pkt_len, frame_off, buf_len);
        return 0;
    }

    if (g_wifi_usb_promisc_en && g_wifi_usb_promisc_cb != NULL) {
        const uint8_t *frame = buf + frame_off;
        uint8_t fc0     = frame[0];
        uint8_t type    = (fc0 >> 2) & 0x3;

        uint16_t copy_len = (pkt_len > WIFI_USB_MAX_FRAME) ? WIFI_USB_MAX_FRAME : pkt_len;
        if (copy_len < pkt_len) {
            ESP_LOGD(TAG, "Frame truncated for callback: %u -> %u bytes", pkt_len, copy_len);
        }

        wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)s_promisc_pkt_buf;
        pkt->rx_ctrl.sig_len  = copy_len;
        pkt->rx_ctrl.channel  = g_wifi_usb_channel;
        pkt->rx_ctrl.rate     = rate_idx;
        
        if (physt && drvinfo_sz >= 4) {
            pkt->rx_ctrl.rssi = decode_rssi(buf + 24, rate_idx < 4);
        } else {
            pkt->rx_ctrl.rssi = 0;
        }
        
        //pkt->rx_ctrl.crc_err  = crc_err;
        //pkt->rx_ctrl.icv_err  = icv_err;
        memcpy(pkt->payload, frame, copy_len);

        wifi_promiscuous_pkt_type_t wtype;
        switch (type) {
            case 0:  wtype = WIFI_USB_PKT_MGMT; break;
            case 1:  wtype = WIFI_USB_PKT_CTRL; break;
            case 2:  wtype = WIFI_USB_PKT_DATA; break;
            default: wtype = WIFI_USB_PKT_MISC; break;
        }
        g_wifi_usb_promisc_cb(pkt, wtype);
    }

    /* Hardware aligns each block to 8 bytes */
    return (block_len + 7) & ~7;
}

void rtl8188_rx_task(void *arg)
{
    ESP_LOGI(TAG, "RX task started");

    usb_transfer_t *transfer;
    ESP_ERROR_CHECK(usb_host_transfer_alloc(4096, 0, &transfer));
    SemaphoreHandle_t sync_sem = xSemaphoreCreateBinary();

    transfer->device_handle = global_dev_hdl;
    transfer->bEndpointAddress = 0x81; // Endpoint 1 BULK IN
    transfer->callback = bulk_transfer_cb;
    transfer->context = sync_sem;

    uint32_t stall_count = 0;

    while (g_wifi_usb_rx_task_should_run) {
        transfer->num_bytes = 4096;

        esp_err_t err = usb_host_transfer_submit(transfer);
        if (err != ESP_OK) {
            ESP_LOGD(TAG, "Bulk IN submit error: %d", err);
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }

        while (xSemaphoreTake(sync_sem, pdMS_TO_TICKS(2000)) != pdTRUE) {
            if (!g_wifi_usb_rx_task_should_run) break;
            stall_count++;
            ESP_LOGD(TAG, "No packets received for %lu s", (unsigned long)(stall_count * 2));
            rtl8188_dump_rx_state();
        }
        if (!g_wifi_usb_rx_task_should_run) break;
        stall_count = 0;

        if (transfer->status == USB_TRANSFER_STATUS_COMPLETED && transfer->actual_num_bytes > 0) {
            const uint8_t *buf = transfer->data_buffer;
            int total_len = transfer->actual_num_bytes;
            int pos = 0;
            int guard = 0;

            while (pos + 24 <= total_len && guard < 64) {
                int consumed = rx_parse_one_block(buf + pos, total_len - pos);
                if (consumed <= 0) break;
                pos += consumed;
                guard++;
            }
        } else if (transfer->status == USB_TRANSFER_STATUS_NO_DEVICE) {
            ESP_LOGW(TAG, "Device disconnected during RX!");
            break;
        } else {
            ESP_LOGD(TAG, "Bulk IN incomplete: status=%d, bytes=%d",
                     transfer->status, transfer->actual_num_bytes);
            vTaskDelay(pdMS_TO_TICKS(10));
        }
    }

    usb_host_transfer_free(transfer);
    vSemaphoreDelete(sync_sem);
    g_wifi_usb_rx_task_hdl = NULL;
    ESP_LOGI(TAG, "RX task stopped");
    vTaskDelete(NULL);
}

#endif