#if defined(CONFIG_IDF_TARGET_ESP32S2) || defined(CONFIG_IDF_TARGET_ESP32S3)

#include "rtl8188e_hal.h"
#include "rtl8188e_usb.h"
#include "rtl8188e_tables.h"
#include "rtl8188eu_fw.h"
#include "rtl8188e_spec.h"

static const char *TAG = "RTL8188_HAL";

/* ------------------------------------------------------------------ *
 *  Power sequence table (ported from Hal8188EPwrSeq.h)
 * ------------------------------------------------------------------ */

#define PWR_CMD_WRITE    0
#define PWR_CMD_POLLING  1
#define PWR_CMD_DELAY    2
#define PWR_CMD_END      3

typedef struct {
    uint16_t offset;
    uint8_t  cmd;
    uint8_t  mask;
    uint8_t  value;
} rtl_pwr_cfg_t;

/* RTL8188E_TRANS_CARDEMU_TO_ACT: from card emulation to active state */
static const rtl_pwr_cfg_t rtl8188e_power_on_flow[] = {
    {0x0006, PWR_CMD_POLLING, (1 << 1),            (1 << 1)},   /* wait for power ready */
    {0x0002, PWR_CMD_WRITE,   (1 << 0) | (1 << 1), 0},          /* baseband reset       */
    {0x0026, PWR_CMD_WRITE,   (1 << 7),            (1 << 7)},   /* schmitt trigger      */
    {0x0005, PWR_CMD_WRITE,   (1 << 7),            0},          /* disable HWPDN        */
    {0x0005, PWR_CMD_WRITE,   (1 << 4) | (1 << 3), 0},          /* disable WL suspend   */
    {0x0005, PWR_CMD_WRITE,   (1 << 0),            (1 << 0)},   /* APFM_ONMAC: turn on MAC */
    {0x0005, PWR_CMD_POLLING, (1 << 0),            0},          /* wait for power-on    */
    {0x0023, PWR_CMD_WRITE,   (1 << 4),            0},          /* LDO normal mode      */
    {0xFFFF, PWR_CMD_END,     0,                   0},
};

/**
 * @brief Executes a Realtek power sequence
 */
static bool rtl8188e_run_pwr_seq(usb_device_handle_t dev, const rtl_pwr_cfg_t *seq, const char *name)
{
    for (int i = 0; seq[i].cmd != PWR_CMD_END; i++) {
        const rtl_pwr_cfg_t *s = &seq[i];

        if (s->cmd == PWR_CMD_WRITE) {
            uint8_t v = rtl_read8(dev, s->offset);
            v = (v & ~s->mask) | (s->value & s->mask);
            rtl_write8(dev, s->offset, v);

        } else if (s->cmd == PWR_CMD_POLLING) {
            bool ok = false;
            uint8_t v = 0;

            for (int t = 0; t < 500; t++) {
                v = rtl_read8(dev, s->offset) & s->mask;
                if (v == (s->value & s->mask)) {
                    ok = true;
                    break;
                }
                vTaskDelay(pdMS_TO_TICKS(1));
            }

            if (!ok) {
                ESP_LOGE(TAG, "%s: polling failed at 0x%04X (read 0x%02X, expected 0x%02X)",
                         name, s->offset, v, (unsigned)(s->value & s->mask));
                return false;
            }

        } else if (s->cmd == PWR_CMD_DELAY) {
            vTaskDelay(pdMS_TO_TICKS(1));
        }
    }

    ESP_LOGD(TAG, "%s: completed", name);
    return true;
}

/**
 * @brief Writes an entry to the LLT (Link List Table) with OP bit polling
 */
static bool rtl8188e_llt_write(usb_device_handle_t dev, uint32_t address, uint32_t data)
{
    uint32_t value = _LLT_INIT_ADDR(address) | _LLT_INIT_DATA(data) | _LLT_OP(_LLT_WRITE_ACCESS);

    rtl_write32(dev, REG_LLT_INIT, value);

    for (int count = 20; count > 0; count--) {
        value = rtl_read32(dev, REG_LLT_INIT);
        if (_LLT_OP_VALUE(value) == _LLT_NO_ACTIVE)
            return true;
    }

    ESP_LOGE(TAG, "LLT: write polling failed at address 0x%02X", (unsigned)address);
    return false;
}

/**
 * @brief Reset the internal 8051 CPU
 */
static void rtl8188e_reset_8051(usb_device_handle_t dev)
{
    uint8_t sys_func = rtl_read8(dev, REG_SYS_FUNC_EN + 1);

    rtl_write8(dev, REG_SYS_FUNC_EN + 1, sys_func & ~(1 << 2));   /* CPUEN off */
    rtl_write8(dev, REG_SYS_FUNC_EN + 1, sys_func | (1 << 2));    /* CPUEN on  */
}

/**
 * @brief Chip power-on sequence
 */
void rtl8188e_power_on(usb_device_handle_t dev)
{
    RTL_PROBE8(REG_NORMAL_SIE_EP + 1);   //0xFE66
    RTL_PROBE8(REG_NORMAL_SIE_EP + 2);   //0xFE67
    RTL_PROBE32(REG_SYS_CFG);            //0x00F0
    RTL_PROBE8(REG_9346CR);              //0x000A
    rtl_write8(dev, REG_EFUSE_ACCESS, 0x69); //0x00CF
    RTL_PROBE16(REG_SYS_FUNC_EN);        //0x0002

    for(int i = 0; i < 0x7F; i++) {
        rtl_write8(dev, REG_EFUSE_CTRL + 1, i);             //0x0031
        RTL_PROBE8(REG_EFUSE_CTRL + 2);                     //0x0032
        rtl_write8(dev, REG_EFUSE_CTRL + 2, 0x20);          //0x0032
        RTL_PROBE8(REG_EFUSE_CTRL + 3);                     //0x0033
        rtl_write8(dev, REG_EFUSE_CTRL + 3, 0x00);          //0x0033
        RTL_PROBE8(REG_EFUSE_CTRL + 3);                     //0x0033
        RTL_PROBE8(REG_EFUSE_CTRL);                         //0x0030
    }

    rtl_write8(dev, REG_EFUSE_ACCESS, 0x00);                //0x00CF
    uint8_t MACID[6] = { 0x70, 0xF1, 0x1C, 0x5E, 0x54, 0x8A };
    for(int i = 0; i < 6; i++) {
        rtl_write8(dev, REG_MACID + i, MACID[i]);           //0x0610 - 0x0615
    }

    uint8_t MACID1[6] = { 0x72, 0xF1, 0x1C, 0x5E, 0x54, 0x8A };
    for(int i = 0; i < 6; i++) {
        rtl_write8(dev, REG_MACID1 + i, MACID1[i]);         //0x0700 - 0x0705
    }

    RTL_PROBE8(REG_AFE_XTAL_CTRL + 1);           //0x0025
    RTL_PROBE8(REG_CR);                          //0x0100
    RTL_PROBE8(REG_SYS_CLKR + 1);                //0x0009
    RTL_PROBE8(REG_WOW_CTRL);                    //0x0690
    RTL_PROBE32(0x0630);                         //0x0630
    RTL_PROBE32(0x0634);                         //0x0634
    RTL_PROBE32(REG_RXPKT_NUM);                  //0x0284
    RTL_PROBE8(REG_RXDMA_STATUS);                //0x0288
    RTL_PROBE32(REG_RXFF_PTR);                   //0x011c
    RTL_PROBE32(REG_MCUTST_1);                   //0x01c0
    RTL_PROBE8(REG_MCUTST_1 + 4);                //0x01c4
    RTL_PROBE8(REG_MCUTST_1 + 7);                //0x01c7

    RTL_PROBE8(REG_HMEBOX_E0);                   //0x0088
    RTL_PROBE8(REG_APS_FSMCO + 2);               //0x0006
    RTL_PROBE8(REG_SYS_CFG + 2);                 //0x00f2
    rtl_write8(dev, REG_SYS_CFG + 2, 0x40);      //0x00f2
    
    if (!rtl8188e_run_pwr_seq(dev, rtl8188e_power_on_flow, "Power-on CARDEMU->ACT"))
        ESP_LOGE(TAG, "Incomplete power-on: chip might not respond");
    
    rtl_write16(dev, REG_CR, 0x0000);            //0x0100
    RTL_PROBE16(REG_CR);                         //0x0100
    rtl_write16(dev, REG_CR, 0x063f);            //0x0100

    ESP_LOGD(TAG, "REG_TXDMA_OFFSET_CHK (0x020C) after power-on: 0x%08X",
             (unsigned int)rtl_read32(dev, REG_TXDMA_OFFSET_CHK));

    RTL_PROBE8(SDIO_REG_HRPWM1);                 //0x0080
    RTL_PROBE8(REG_RSV_CTRL);                    //0x001c
    rtl_write8(dev, REG_RSV_CTRL, 0x00);         //0x001c
    RTL_PROBE8(REG_RSV_CTRL + 1);                //0x001d
    rtl_write8(dev, REG_RSV_CTRL + 1, 0x78);     //0x001d
    RTL_PROBE8(REG_SYS_FUNC_EN + 1);             //0x0003
    rtl_write8(dev, REG_SYS_FUNC_EN + 1, 0xfc);  //0x0003
    RTL_PROBE8(SDIO_REG_HRPWM2);                 //0x0082
    rtl_write8(dev, SDIO_REG_HRPWM2, 0x00);      //0x0082
    RTL_PROBE8(SDIO_REG_HRPWM2);                 //0x0082
    rtl_write8(dev, SDIO_REG_HRPWM2, 0x00);      //0x0082

    ESP_LOGD(TAG, "Chip powered on.");
}

/**
 * @brief Validate the 32-byte header of the firmware image
 */
static bool rtl8188e_check_firmware_header(void)
{
    const uint8_t *h = array_mp_8188e_s_fw_nic;

    uint16_t signature   = (uint16_t)h[0] | ((uint16_t)h[1] << 8);
    uint16_t version     = (uint16_t)h[4] | ((uint16_t)h[5] << 8);
    uint8_t  subversion  = h[6];
    uint16_t ramcodesize = (uint16_t)h[12] | ((uint16_t)h[13] << 8);
    uint32_t payload     = array_length_mp_8188e_s_fw_nic - 32;

    ESP_LOGD(TAG, "FW Header: sig=0x%04X v%u.%u ramcodesize=%u payload=%u",
             signature, version, subversion, ramcodesize, (unsigned int)payload);

    if ((signature & 0xFFF0) != 0x88E0) {
        ESP_LOGE(TAG, "Invalid signature 0x%04X for 8188E (expected 0x88Ex)", signature);
        return false;
    }

    if (ramcodesize != payload)
        ESP_LOGW(TAG, "Header declares %u bytes of code but payload is %u",
                 ramcodesize, (unsigned int)payload);

    return true;
}

/**
 * @brief Load firmware into chip RAM in pages
 */
esp_err_t rtl8188e_load_firmware(usb_device_handle_t dev)
{
    if (!rtl8188e_check_firmware_header())
        return ESP_FAIL;

    /* Stop 8051 if it is already executing from RAM */
    if (rtl_read8(dev, SDIO_REG_HRPWM1) & (1 << 7)) {
        ESP_LOGD(TAG, "8051 already in RAM: stopping before reload");
        rtl_write8(dev, SDIO_REG_HRPWM1, 0x00);
        rtl8188e_reset_8051(dev);
    }

    /* _FWDownloadEnable(TRUE) */
    rtl_write8(dev, SDIO_REG_HRPWM1,
               rtl_read8(dev, SDIO_REG_HRPWM1) | MCUFWDL_EN);
    rtl_write8(dev, SDIO_REG_HRPWM2,
               rtl_read8(dev, SDIO_REG_HRPWM2) & 0xF7);

    /* Reset checksum flag before writing */
    rtl_write8(dev, SDIO_REG_HRPWM1,
               rtl_read8(dev, SDIO_REG_HRPWM1) | MCUFWDL_CHKSUM_RPT);

    /* Skip the first 32 bytes (header) */
    uint32_t offset = 32;
    uint32_t remain = array_length_mp_8188e_s_fw_nic - 32;
    uint8_t  page   = 0;

    while (remain > 0) {
        uint32_t block_len    = (remain > 4096) ? 4096 : remain;
        uint32_t block_remain = block_len;
        uint16_t dest_addr    = FW_START_ADDRESS;

        uint8_t sel = (rtl_read8(dev, SDIO_REG_HRPWM2) & 0xF8) | (page & 0x07);
        rtl_write8(dev, SDIO_REG_HRPWM2, sel);              //0x0082

        ESP_LOGD(TAG, "Writing %u bytes for Page %u...", (unsigned int)block_len, page);

        while (block_remain > 0) {
            uint16_t chunk_len = (block_remain > FW_CHUNK_SIZE)
                               ? FW_CHUNK_SIZE : (uint16_t)block_remain;

            esp_err_t err = rtl_write_block(dev, dest_addr,
                                            &array_mp_8188e_s_fw_nic[offset],
                                            chunk_len);
            if (err != ESP_OK) {
                ESP_LOGE(TAG, "Fatal error writing firmware at offset %u", (unsigned int)offset);
                return ESP_FAIL;
            }
            offset       += chunk_len;
            dest_addr    += chunk_len;
            block_remain -= chunk_len;
        }

        remain -= block_len;
        page++;
    }

    ESP_LOGD(TAG, "Firmware loaded (%u bytes in %u pages).",
             (unsigned int)(array_length_mp_8188e_s_fw_nic - 32), page);
    return ESP_OK;
}

/**
 * @brief Close download, reset 8051 and wait for firmware readiness
 */
void rtl8188e_start_firmware(usb_device_handle_t dev)
{
    /* _FWDownloadEnable(FALSE) */
    rtl_write8(dev, SDIO_REG_HRPWM1,
               rtl_read8(dev, SDIO_REG_HRPWM1) & ~MCUFWDL_EN);   //0x0080
    rtl_write8(dev, SDIO_REG_HRPWM1 + 1, 0x00);                  //0x0081

    /* Wait for checksum report */
    uint32_t fwdl = 0;
    bool checksum_ok = false;

    for (int i = 0; i < 100; i++) {
        fwdl = rtl_read32(dev, SDIO_REG_HRPWM1);   //0x0080
        if (fwdl & MCUFWDL_CHKSUM_RPT) {
            checksum_ok = true;
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(1));
    }

    if (!checksum_ok) {
        ESP_LOGE(TAG, "Firmware checksum never reported (0x0080=0x%08X)", (unsigned int)fwdl);
        return;
    }
    ESP_LOGD(TAG, "Firmware checksum OK (0x0080=0x%08X)", (unsigned int)fwdl);

    /* Raise MCUFWDL_RDY and clear WINTINI_RDY */
    fwdl = rtl_read32(dev, SDIO_REG_HRPWM1);
    fwdl |=  MCUFWDL_RDY;
    fwdl &= ~MCUFWDL_WINTINI_RDY;
    rtl_write32(dev, SDIO_REG_HRPWM1, fwdl);                 //0x0080

    rtl8188e_reset_8051(dev);

    ESP_LOGD(TAG, "After 8051 reset: 0x0003=0x%02X 0x0008=0x%02X 0x001C=0x%02X 0x001D=0x%02X",
             rtl_read8(dev, 0x0003), rtl_read8(dev, 0x0008),
             rtl_read8(dev, 0x001C), rtl_read8(dev, 0x001D));

    /* Wait for WINTINI_RDY */
    uint32_t fw_status = 0;
    bool fw_ready = false;

    for (int i = 0; i < 50; i++) {
        fw_status = rtl_read32(dev, SDIO_REG_HRPWM1);   //0x0080
        if (fw_status & MCUFWDL_WINTINI_RDY) {
            fw_ready = true;
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(10));
    }

    if (fw_ready)
        ESP_LOGI(TAG, "Firmware started and READY (0x0080=0x%08X).", (unsigned int)fw_status);
    else
        ESP_LOGE(TAG, "Firmware NOT ready: 0x0080=0x%08X (missing WINTINI_RDY)", (unsigned int)fw_status);
}

/**
 * @brief Initialize the MAC registers for the RTL8188E chip
 */
void rtl8188e_init_mac(usb_device_handle_t dev_hdl)
{
    ESP_LOGD(TAG, "Configuring MAC registers...");
    int mac_reg_count = rtl8188e_mac_reg_table_len;
    for(int i = 0; i < mac_reg_count; i++) {
        uint16_t reg_addr = rtl8188e_mac_reg_table[i][0];
        uint8_t  reg_val  = rtl8188e_mac_reg_table[i][1];

        rtl_write8(dev_hdl, reg_addr, reg_val);
    }
    ESP_LOGD(TAG, "MAC Initialization complete! (%d registers written)", mac_reg_count);
}

/**
 * @brief Reserve pages for TX queues and set RX boundary (must be done before FW)
 */
void rtl8188e_init_queue_reserved_page(usb_device_handle_t dev_hdl)
{
    ESP_LOGD(TAG, "Reserving queue pages (RQPN) and RX boundary...");

    rtl_write8(dev_hdl, REG_RQPN_NPQ, RQPN_NPQ_8188E);
    rtl_write32(dev_hdl, REG_RQPN,
                (1u << 31) |                             // LD_RQPN: apply values
                ((uint32_t)RQPN_PUBQ_8188E << 16) |      // PUBQ
                ((uint32_t)RQPN_LPQ_8188E  << 8)  |      // LPQ
                 (uint32_t)RQPN_HPQ_8188E);              // HPQ

    /* TX/RX page size = 128 bytes */
    rtl_write8(dev_hdl, REG_PBP, 0x11);

    /* RX FIFO boundary */
    rtl_write16(dev_hdl, REG_TRXFF_BNDY + 2, TRXFF_BOUNDARY_8188E);

    /* InitNormalChipTwoOutEpPriority */
    uint16_t trxdma_pre = rtl_read16(dev_hdl, REG_TRXDMA_CTRL);
    uint16_t trxdma_new = (uint16_t)((trxdma_pre & 0x0007) |
                                     (TRXDMA_CTRL_REAL_VALUE_16 & 0xFFF0));
    rtl_write16(dev_hdl, REG_TRXDMA_CTRL, trxdma_new);
    ESP_LOGD(TAG, "REG_TRXDMA_CTRL (0x010C): 0x%04X -> 0x%04X", trxdma_pre, trxdma_new);
}

/**
 * @brief Set TX buffer boundaries and build the LLT (Link List Table)
 */
void rtl8188e_init_trx_buffer(usb_device_handle_t dev_hdl)
{
    ESP_LOGD(TAG, "Setting TX FIFO boundaries and building LLT...");

    /* TX Buffer boundary */
    rtl_write8(dev_hdl, REG_TXPKTBUF_BCNQ_BDNY,      TX_PAGE_BOUNDARY_8188E);
    rtl_write8(dev_hdl, REG_TXPKTBUF_MGQ_BDNY,       TX_PAGE_BOUNDARY_8188E);
    rtl_write8(dev_hdl, REG_TXPKTBUF_WMAC_LBK_BF_HD, TX_PAGE_BOUNDARY_8188E);
    rtl_write8(dev_hdl, REG_TRXFF_BNDY,              TX_PAGE_BOUNDARY_8188E);
    rtl_write8(dev_hdl, REG_TDECTRL + 1,             TX_PAGE_BOUNDARY_8188E);

    /* Build LLT */
    bool llt_ok = true;
    for (uint32_t i = 0; llt_ok && i < (TX_PAGE_BOUNDARY_8188E - 1); i++) {
        llt_ok = rtl8188e_llt_write(dev_hdl, i, i + 1);
    }
    if (llt_ok)
        llt_ok = rtl8188e_llt_write(dev_hdl, TX_PAGE_BOUNDARY_8188E - 1, 0xFF);
    
    /* LLT Ring buffer */
    for (uint32_t i = TX_PAGE_BOUNDARY_8188E; llt_ok && i < LAST_ENTRY_OF_TX_PKT_BUFFER_8188E; i++) {
        llt_ok = rtl8188e_llt_write(dev_hdl, i, i + 1);
    }
    if (llt_ok)
        llt_ok = rtl8188e_llt_write(dev_hdl, LAST_ENTRY_OF_TX_PKT_BUFFER_8188E, TX_PAGE_BOUNDARY_8188E);

    if (!llt_ok) {
        ESP_LOGE(TAG, "LLT: construction ABORTED due to write failure - TX will not work");
    } else {
        ESP_LOGD(TAG, "LLT built: TX 0x00..0x%02X, beacon ring 0x%02X..0x%02X",
                 (unsigned)(TX_PAGE_BOUNDARY_8188E - 1),
                 (unsigned)TX_PAGE_BOUNDARY_8188E,
                 (unsigned)LAST_ENTRY_OF_TX_PKT_BUFFER_8188E);
    }

    /* Driver info block size */
    rtl_write8(dev_hdl, REG_RX_DRVINFO_SZ, 0x04);
}

/**
 * @brief Final MAC and DMA power up
 */
void rtl8188e_start_radio(usb_device_handle_t dev_hdl)
{
    ESP_LOGD(TAG, "=== FINAL MAC AND DMA POWER UP ===");

    /* Set AP Mode and enable MAC/DMA engines */
    rtl_write32(dev_hdl, REG_CR, 0x0003063F); 

    uint8_t cr = rtl_read8(dev_hdl, REG_CR);
    cr |= 0xFF; // MACTXEN, MACRXEN, TXDMA_EN, RXDMA_EN, etc.
    rtl_write8(dev_hdl, REG_CR, cr);

    /* Enable RX Aggregation */
    rtl_write8(dev_hdl, REG_USB_SPECIAL_OPTION, USB_SPECIAL_OPTION_REAL_VALUE);   // 0xFE55 = 0x08
    rtl_write8(dev_hdl, REG_USB_UNKNOWN_0xFE5D, USB_UNKNOWN_0xFE5D_REAL_VALUE);   // 0xFE5D = 0x08
    rtl_write8(dev_hdl, REG_USB_UNKNOWN_0xFE5C, USB_UNKNOWN_0xFE5C_REAL_VALUE);   // 0xFE5C = 0x06

    /* Release TX queues */
    rtl_write8(dev_hdl, REG_TXPAUSE, 0x00);

    /* Rewrite MAC IDs to prevent FW overwrite */
    {
        uint8_t macid[6]  = { 0x70, 0xF1, 0x1C, 0x5E, 0x54, 0x8A };
        uint8_t macid1[6] = { 0x72, 0xF1, 0x1C, 0x5E, 0x54, 0x8A };
        for (int i = 0; i < 6; i++) {
            rtl_write8(dev_hdl, REG_MACID + i, macid[i]);    // 0x0610 - 0x0615
        }
        for (int i = 0; i < 6; i++) {
            rtl_write8(dev_hdl, REG_MACID1 + i, macid1[i]);  // 0x0700 - 0x0705
        }
    }

    /* Init EDCA parameters */
    rtl_write16(dev_hdl, REG_SPEC_SIFS,     0x100A);
    rtl_write16(dev_hdl, REG_MAC_SPEC_SIFS, 0x100A);
    rtl_write16(dev_hdl, REG_SIFS_CTX,      0x100A);
    rtl_write16(dev_hdl, REG_SIFS_TRX,      0x100A);
    rtl_write32(dev_hdl, REG_EDCA_BE_PARAM, 0x005EA42B);
    rtl_write32(dev_hdl, REG_EDCA_BK_PARAM, 0x0000A44F);
    rtl_write32(dev_hdl, REG_EDCA_VI_PARAM, 0x005EA324);
    rtl_write32(dev_hdl, REG_EDCA_VO_PARAM, 0x002FA226);

    /* Init Retry Function */
    rtl_write8(dev_hdl, REG_FWHW_TXQ_CTRL,
               rtl_read8(dev_hdl, REG_FWHW_TXQ_CTRL) | EN_AMPDU_RTY_NEW);
    rtl_write8(dev_hdl, REG_ACKTO, 0x40);

    /* Enable dropping of incorrect Bulk Out data */
    rtl_write16(dev_hdl, REG_TXDMA_OFFSET_CHK,
                rtl_read16(dev_hdl, REG_TXDMA_OFFSET_CHK) | DROP_DATA_EN);

    /* Enable TX Report & Tx Report Timer */
    rtl_write8(dev_hdl, REG_TX_RPT_CTRL, rtl_read8(dev_hdl, REG_TX_RPT_CTRL) | 0x03);   //0x04ec
    rtl_write8(dev_hdl, REG_TX_RPT_CTRL + 1, 0x02);                                     //0x04ed
    rtl_write16(dev_hdl, REG_TX_RPT_TIME, 0xcdf0);                                      //0x04f0
    rtl_write8(dev_hdl, REG_EARLY_MODE_CONTROL, 0x00);                                  //0x04d0

    /* Setup MACID NO LINK registers */
    rtl_write32(dev_hdl, REG_MACID_NO_LINK_0, 0xFFFFFFFF);
    rtl_write32(dev_hdl, REG_MACID_NO_LINK_1, 0xFFFFFFFF);

    /* Turn on BB (Baseband) */
    {
        uint32_t rfmod = rtl_read32(dev_hdl, REG_FPGA0_RFMOD);
        rfmod |= BB_CCK_EN | BB_OFDM_EN;
        rtl_write32(dev_hdl, REG_FPGA0_RFMOD, rfmod);
    }

    /* Invalidate CAM entries */
    rtl_write32(dev_hdl, REG_CAMCMD, (1u << 31) | (1u << 30));

    /* Misc timing and limits */
    rtl_write16(dev_hdl, REG_RL, 0x3030); 
    rtl_write32(dev_hdl, REG_RRSR, 0x000FFFF1); 
    rtl_write16(dev_hdl, REG_PKT_VO_VI_LIFE_TIME, 0x0400);
    rtl_write16(dev_hdl, REG_PKT_BE_BK_LIFE_TIME, 0x0400);
    rtl_write8(dev_hdl, REG_NAV_UPPER, 0x00); 

    /* Disable BAR */
    rtl_write32(dev_hdl, REG_BAR_MODE_CTRL, 0x0201FFFF);

    /* HW SEQ CTRL */
    rtl_write8(dev_hdl, REG_HWSEQ_CTRL, 0xFF);

    /* Enable Tx report */
    rtl_write8(dev_hdl, REG_FWHW_TXQ_CTRL + 1,
    rtl_read8(dev_hdl, REG_FWHW_TXQ_CTRL + 1) | 0x0F);

    /* Update Tx report time */
    rtl_write16(dev_hdl, REG_TX_RPT_TIME, 0x3df0);

    /* Early mode control settings */
    rtl_write8(dev_hdl, REG_EARLY_MODE_CONTROL + 3, 0x01);

    /* USB HRPWM */
    rtl_write8(dev_hdl, REG_USB_HRPWM, 0x00);

    /* Enable dropping of incorrect Bulk Out data (redundant but matches driver spec) */
    rtl_write16(dev_hdl, REG_TXDMA_OFFSET_CHK,
    rtl_read16(dev_hdl, REG_TXDMA_OFFSET_CHK) | DROP_DATA_EN);

    /* XMIT ACK for management frames */
    {
        uint32_t txq_ctrl = rtl_read32(dev_hdl, REG_FWHW_TXQ_CTRL);
        txq_ctrl |= (1u << 12);
        rtl_write32(dev_hdl, REG_FWHW_TXQ_CTRL, txq_ctrl);
    }

    ESP_LOGD(TAG, "MAC and DMA are online!");
}

#endif