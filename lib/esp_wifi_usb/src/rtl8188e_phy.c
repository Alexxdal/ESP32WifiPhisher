#include "rtl8188e_phy.h"
#include "rtl8188e_usb.h"
#include "rtl8188e_tables.h"

static const char *TAG = "RTL8188_PHY";

/* Initial value: last write to 0x018 from RadioA table. 
 * Bit 15 is the LC calibration trigger (self-clearing). */
uint32_t g_rf_chnlbw_val = 0x0000F407;

/**
 * @brief Read-modify-write on a baseband register with a bit mask
 */
void rtl_bb_write_mask(usb_device_handle_t dev_hdl, uint16_t reg, uint32_t mask, uint32_t value)
{
    uint32_t shift = 0;
    while (((mask >> shift) & 1) == 0) shift++;

    uint32_t orig = rtl_read32(dev_hdl, reg);
    orig = (orig & ~mask) | ((value << shift) & mask);
    rtl_write32(dev_hdl, reg, orig);
}

uint32_t rtl_bb_read_mask(usb_device_handle_t dev_hdl, uint16_t reg, uint32_t mask)
{
    uint32_t shift = 0;
    while (((mask >> shift) & 1) == 0) shift++;
    return (rtl_read32(dev_hdl, reg) & mask) >> shift;
}

/**
 * @brief Writes an RF chip register via LSSI serial interface
 */
void rtl_write_rf(usb_device_handle_t dev_hdl, uint16_t rf_addr, uint32_t data)
{
    uint32_t data_and_addr = (((uint32_t)rf_addr << 20) | (data & 0x000FFFFF)) & 0x0FFFFFFF;
    rtl_write32(dev_hdl, REG_FPGA0_XA_LSSI_PARM, data_and_addr);
}

/**
 * @brief Reads an RF chip register (used to verify LSSI bus health)
 */
uint32_t rtl_read_rf(usb_device_handle_t dev_hdl, uint8_t rf_addr)
{
    uint32_t hssi = rtl_read32(dev_hdl, REG_FPGA0_XA_HSSI_PARM2);
    uint32_t val  = (hssi & ~0x7F800000u) | (((uint32_t)rf_addr << 23) & 0x7F800000u);

    hssi &= ~(1u << 31);                 /* read edge low */
    rtl_write32(dev_hdl, REG_FPGA0_XA_HSSI_PARM2, hssi);
    rtl_write32(dev_hdl, REG_FPGA0_XA_HSSI_PARM2, val | (1u << 31));
    rtl_write32(dev_hdl, REG_FPGA0_XA_HSSI_PARM2, hssi | (1u << 31));

    uint32_t parm1 = rtl_read32(dev_hdl, REG_FPGA0_XA_HSSI_PARM1);
    uint32_t rb = (parm1 & (1u << 8))    /* PI mode? */
                ? rtl_read32(dev_hdl, REG_HSPI_XA_READBACK)
                : rtl_read32(dev_hdl, REG_FPGA0_XA_LSSI_READBACK);

    return rb & 0xFFFFF;
}

/**
 * @brief Applies a single row of the RadioA table (handling pseudo-addr delays)
 */
static void rtl8188e_config_rf_reg(usb_device_handle_t dev_hdl, uint32_t addr, uint32_t data)
{
    switch (addr) {
    case 0xFFE: vTaskDelay(pdMS_TO_TICKS(50)); break;
    case 0xFD:  vTaskDelay(pdMS_TO_TICKS(5));  break;
    case 0xFC:  vTaskDelay(pdMS_TO_TICKS(1));  break;
    case 0xFB:  /* 50us */
    case 0xFA:  /* 5us  */
    case 0xF9:  /* 1us  */
        break;  /* covered by USB latency */
    default:
        rtl_write_rf(dev_hdl, (uint16_t)addr, data);
        break;
    }
}

/* "Hardware assumed" values used by the table condition validator */
#define RTL8188E_COND_BOARD_TYPE        0x00
#define RTL8188E_COND_CUT_VERSION       0x0F
#define RTL8188E_COND_PACKAGE_TYPE      0x0F
#define RTL8188E_COND_SUPPORT_INTERFACE 0x02 /* ODM_ITRF_USB */

/**
 * @brief Remaps raw board_type bits to the order expected by check_positive()
 */
static uint32_t rtl8188e_board_type_remap(uint8_t board_type)
{
    return (((uint32_t)(board_type >> 4) & 1) << 0) |
           (((uint32_t)(board_type >> 3) & 1) << 1) |
           (((uint32_t)(board_type >> 7) & 1) << 2) |
           (((uint32_t)(board_type >> 6) & 1) << 3) |
           (((uint32_t)(board_type >> 2) & 1) << 4) |
           (((uint32_t)(board_type >> 1) & 1) << 5) |
           (((uint32_t)(board_type >> 5) & 1) << 6);
}

/**
 * @brief Evaluates whether a conditional block in the PHY tables applies to this HW
 */
static bool rtl8188e_check_positive(uint32_t cond1, uint32_t cond2, uint32_t cond3, uint32_t cond4)
{
    (void)cond3; 

    uint32_t driver1 = ((uint32_t)RTL8188E_COND_CUT_VERSION << 24) |
                        (((uint32_t)RTL8188E_COND_SUPPORT_INTERFACE & 0xF0) << 16) |
                        ((uint32_t)RTL8188E_COND_PACKAGE_TYPE << 12) |
                        (((uint32_t)RTL8188E_COND_SUPPORT_INTERFACE & 0x0F) << 8) |
                        rtl8188e_board_type_remap(RTL8188E_COND_BOARD_TYPE);
    uint32_t driver2 = 0; 
    uint32_t driver4 = 0;

    if ((cond1 & 0x0000F000) != 0 && (cond1 & 0x0000F000) != (driver1 & 0x0000F000))
        return false;
    if ((cond1 & 0x0F000000) != 0 && (cond1 & 0x0F000000) != (driver1 & 0x0F000000))
        return false;

    uint32_t c1 = cond1 & 0x00FF0FFF;
    uint32_t d1 = driver1 & 0x00FF0FFF;
    if ((c1 & d1) != c1)
        return false;

    if ((c1 & 0x0F) == 0)
        return true; 

    uint32_t bit_mask = 0;
    if (c1 & 0x1) bit_mask |= 0x000000FF;
    if (c1 & 0x2) bit_mask |= 0x0000FF00;
    if (c1 & 0x4) bit_mask |= 0x00FF0000;
    if (c1 & 0x8) bit_mask |= 0xFF000000;

    return ((cond2 & bit_mask) == (driver2 & bit_mask)) &&
           ((cond4 & bit_mask) == (driver4 & bit_mask));
}

/**
 * @brief Process the PHY initialization array for the RTL8188E chip
 */
static void rtl8188e_process_phy_array(usb_device_handle_t dev_hdl, const uint32_t* array, uint32_t len)
{
    bool is_matched = true;
    bool is_skipped = false;
    uint32_t pre_v1 = 0, pre_v2 = 0;

    for (uint32_t i = 0; i + 1 < len; i += 2) {
        uint32_t v1 = array[i];
        uint32_t v2 = array[i + 1];

        if (v1 & 0xC0000000) {
            if (v1 & 0x80000000) { 
                uint8_t cond = (v1 & 0x30000000) >> 28;

                if (cond == 3) {            /* ENDIF */
                    is_matched = true;
                    is_skipped = false;
                } else if (cond == 2) {     /* ELSE */
                    is_matched = !is_skipped;
                } else {                    /* IF / ELSE IF */
                    pre_v1 = v1;
                    pre_v2 = v2;
                }
            } else { 
                if (!is_skipped) {
                    if (rtl8188e_check_positive(pre_v1, pre_v2, v1, v2)) {
                        is_matched = true;
                        is_skipped = true;
                    } else {
                        is_matched = false;
                        is_skipped = false;
                    }
                } else {
                    is_matched = false;
                }
            }
        }
        else {
            if (is_matched) {
                rtl_write32(dev_hdl, v1, v2);
            }
        }
    }
}

/**
 * @brief Same as rtl8188e_process_phy_array, but writes to RF chip instead of BB
 */
static void rtl8188e_process_rf_array(usb_device_handle_t dev_hdl, const uint32_t* array, uint32_t len)
{
    bool is_matched = true;
    bool is_skipped = false;
    uint32_t pre_v1 = 0, pre_v2 = 0;

    for (uint32_t i = 0; i + 1 < len; i += 2) {
        uint32_t v1 = array[i];
        uint32_t v2 = array[i + 1];

        if (v1 & 0xC0000000) {
            if (v1 & 0x80000000) {
                uint8_t cond = (v1 & 0x30000000) >> 28;

                if (cond == 3) {            /* ENDIF */
                    is_matched = true;
                    is_skipped = false;
                } else if (cond == 2) {     /* ELSE */
                    is_matched = !is_skipped;
                } else {                    /* IF / ELSE IF */
                    pre_v1 = v1;
                    pre_v2 = v2;
                }
            } else { 
                if (!is_skipped) {
                    if (rtl8188e_check_positive(pre_v1, pre_v2, v1, v2)) {
                        is_matched = true;
                        is_skipped = true;
                    } else {
                        is_matched = false;
                        is_skipped = false;
                    }
                } else {
                    is_matched = false;
                }
            }
        } else {
            if (is_matched) {
                rtl8188e_config_rf_reg(dev_hdl, v1, v2);
            }
        }
    }
}

/**
 * @brief Power on Baseband and RF BEFORE loading PHY tables
 */
void rtl8188e_enable_bb_rf(usb_device_handle_t dev_hdl)
{
    ESP_LOGD(TAG, "Powering on Baseband and RF...");

    uint16_t sys_func = rtl_read16(dev_hdl, 0x0002);
    sys_func |= (1 << 0) | (1 << 1) | (1 << 13); /* FEN_BBRSTB | FEN_BB_GLB_RSTn | FEN_DIO_RF */
    rtl_write16(dev_hdl, 0x0002, sys_func);

    /* RF_EN | RF_RSTB | RF_SDMRSTB */
    rtl_write8(dev_hdl, 0x001F, 0x07);

    /* FEN_USBA | FEN_USBD | FEN_BB_GLB_RSTn | FEN_BBRSTB: USB stays alive */
    rtl_write8(dev_hdl, 0x0002, 0x17);

    uint8_t xtal_cap = 0x20;
    rtl_bb_write_mask(dev_hdl, 0x0024, XTAL_CAP_MASK,
                      (uint32_t)xtal_cap | ((uint32_t)xtal_cap << 6));
    ESP_LOGD(TAG, "Crystal cap set (0x0024=0x%08X)",
             (unsigned int)rtl_read32(dev_hdl, 0x0024));
}

/**
 * @brief Unlocks and resets baseband false alarm / CCA counters
 */
void rtl8188e_reset_phy_counters(usb_device_handle_t dev_hdl)
{
    /* OFDM reset pulse */
    rtl_bb_write_mask(dev_hdl, 0x0C0C, 1u << 31, 1);
    rtl_bb_write_mask(dev_hdl, 0x0C0C, 1u << 31, 0);
    rtl_bb_write_mask(dev_hdl, 0x0D00, 1u << 27, 1);
    rtl_bb_write_mask(dev_hdl, 0x0D00, 1u << 27, 0);

    /* CCK: [13:12] = 2 starts counting */
    rtl_bb_write_mask(dev_hdl, 0x0A2C, 3u << 12, 0);
    rtl_bb_write_mask(dev_hdl, 0x0A2C, 3u << 12, 2);

    /* Set counters to counting mode */
    rtl_bb_write_mask(dev_hdl, 0x0C00, 1u << 31, 0);
    rtl_bb_write_mask(dev_hdl, 0x0D00, 1u << 31, 0);
}

/**
 * @brief Applies the "PG" table (power-per-rate) to TX_AGC registers
 */
void rtl8188e_apply_tx_power_by_rate(usb_device_handle_t dev_hdl)
{
    static const uint32_t pg_data[][3] = {
        {0x0e08, 0x0000ff00, 0x00003800},
        {0x086c, 0xffffff00, 0x32343600},
        {0x0e00, 0xffffffff, 0x40424446},
        {0x0e04, 0xffffffff, 0x28323638},
        {0x0e10, 0xffffffff, 0x38404244},
        {0x0e14, 0xffffffff, 0x26303436}
    };

    for (size_t i = 0; i < sizeof(pg_data) / sizeof(pg_data[0]); i++) {
        uint32_t reg = pg_data[i][0];
        uint32_t mask = pg_data[i][1];
        uint32_t val = pg_data[i][2];
        if (mask == 0xFFFFFFFF) {
            rtl_write32(dev_hdl, reg, val);
        } else {
            uint32_t orig = rtl_read32(dev_hdl, reg);
            orig = (orig & ~mask) | (val & mask);
            rtl_write32(dev_hdl, reg, orig);
        }
    }
}

/**
 * @brief Initialize Baseband and RF
 */
void rtl8188e_init_bb_rf(usb_device_handle_t dev_hdl)
{
    ESP_LOGD(TAG, "AGC Calibration...");
    uint32_t agc_len = rtl8188e_agc_tab_len;
    rtl8188e_process_phy_array(dev_hdl, rtl8188e_agc_tab, agc_len);

    ESP_LOGD(TAG, "PHY Calibration...");
    uint32_t phy_len = rtl8188e_phy_reg_len;
    rtl8188e_process_phy_array(dev_hdl, rtl8188e_phy_reg, phy_len);

    ESP_LOGD(TAG, "PG Calibration...");
    rtl8188e_apply_tx_power_by_rate(dev_hdl);

    ESP_LOGD(TAG, "BB and RF configured successfully!");
}

/**
 * @brief Load RadioA table into RF transceiver
 */
void rtl8188e_init_rf(usb_device_handle_t dev_hdl)
{
    ESP_LOGD(TAG, "RF RadioA Configuration...");

    uint32_t rfenv_backup = rtl_bb_read_mask(dev_hdl, REG_FPGA0_XAB_RF_INT_SW, BRFSI_RFENV);

    rtl_bb_write_mask(dev_hdl, REG_FPGA0_XA_RF_INT_OE, BRFSI_RFENV << 16, 0x1);
    rtl_bb_write_mask(dev_hdl, REG_FPGA0_XA_RF_INT_OE, BRFSI_RFENV, 0x1);

    /* Address/data length = 0 -> standard LSSI mode (8+20 bit) */
    rtl_bb_write_mask(dev_hdl, REG_FPGA0_XA_HSSI_PARM2, 0x400, 0x0);
    rtl_bb_write_mask(dev_hdl, REG_FPGA0_XA_HSSI_PARM2, 0x800, 0x0);

    uint32_t radioa_len = rtl8188e_radioa_tab_len;
    rtl8188e_process_rf_array(dev_hdl, rtl8188e_radioa_tab, radioa_len);

    rtl_bb_write_mask(dev_hdl, REG_FPGA0_XAB_RF_INT_SW, BRFSI_RFENV, rfenv_backup);

    uint32_t rf_mode = rtl_read32(dev_hdl, REG_FPGA0_RFMOD);
    rf_mode |= (1u << 24) | (1u << 25);   /* FPGA_RF_MODE_CCK | FPGA_RF_MODE_OFDM */
    rtl_write32(dev_hdl, REG_FPGA0_RFMOD, rf_mode);

    rtl8188e_reset_phy_counters(dev_hdl);

    ESP_LOGD(TAG, "RF RadioA configured! (0x800=0x%08X, CCK+OFDM enabled)",
             (unsigned int)rtl_read32(dev_hdl, REG_FPGA0_RFMOD));
}

/**
 * @brief IGI sweep diagnostic function
 */
void rtl8188e_igi_sweep_diagnostic(usb_device_handle_t dev_hdl)
{
    static const uint8_t candidates[] = { 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x50 };
    uint8_t orig_igi = rtl_read8(dev_hdl, 0x0C50);

    ESP_LOGD(TAG, "=== IGI Sweep Diagnostic (original value 0x%02X) ===", (unsigned int)orig_igi);

    for (size_t i = 0; i < sizeof(candidates); i++) {
        rtl_write8(dev_hdl, 0x0C50, candidates[i]);

        rtl_bb_write_mask(dev_hdl, 0x0C0C, 1u << 31, 1);
        rtl_bb_write_mask(dev_hdl, 0x0C0C, 1u << 31, 0);
        rtl_bb_write_mask(dev_hdl, 0x0D00, 1u << 27, 1);
        rtl_bb_write_mask(dev_hdl, 0x0D00, 1u << 27, 0);
        rtl_bb_write_mask(dev_hdl, 0x0A2C, 3u << 12, 0);
        rtl_bb_write_mask(dev_hdl, 0x0A2C, 3u << 12, 2);
        rtl_bb_write_mask(dev_hdl, 0x0C00, 1u << 31, 0);
        rtl_bb_write_mask(dev_hdl, 0x0D00, 1u << 31, 0);

        vTaskDelay(pdMS_TO_TICKS(500));

        rtl_bb_write_mask(dev_hdl, 0x0C00, 1u << 31, 1);
        rtl_bb_write_mask(dev_hdl, 0x0D00, 1u << 31, 1);

        uint32_t t2  = rtl_read32(dev_hdl, 0x0DA0);
        uint32_t a60 = rtl_read32(dev_hdl, 0x0A60);
        unsigned int ofdm_cca = t2 & 0xFFFF;
        unsigned int cck_cca  = ((a60 & 0x00FF) << 8) | ((a60 & 0xFF00) >> 8);

        rtl_bb_write_mask(dev_hdl, 0x0C00, 1u << 31, 0);
        rtl_bb_write_mask(dev_hdl, 0x0D00, 1u << 31, 0);

        ESP_LOGD(TAG, "  IGI=0x%02X -> OFDM_CCA=%u CCK_CCA=%u (in 500ms)",
                 candidates[i], ofdm_cca, cck_cca);
    }

    rtl_write8(dev_hdl, 0x0C50, orig_igi);
    ESP_LOGD(TAG, "=== Sweep finished, IGI restored to 0x%02X ===", (unsigned int)orig_igi);
}

/**
 * @brief Tunes the radio to a 2.4 GHz channel (1-14), 20 MHz bandwidth
 */
void rtl8188e_set_channel(usb_device_handle_t dev_hdl, uint8_t channel)
{
    if (channel < 1 || channel > 14) {
        ESP_LOGE(TAG, "Invalid channel %d", channel);
        return;
    }

    /* Baseband in 20 MHz */
    rtl_bb_write_mask(dev_hdl, REG_FPGA0_RFMOD, 0x1, 0x0);
    rtl_bb_write_mask(dev_hdl, REG_FPGA1_RFMOD, 0x1, 0x0);
    rtl_bb_write_mask(dev_hdl, REG_FPGA0_ANALOG_PARM2, (1 << 10), 0x1);

    /* RF 0x18: bit 9..0 = channel, bit 10,11 = 20 MHz */
    g_rf_chnlbw_val = (g_rf_chnlbw_val & 0xFFFFFC00) | (channel & 0x3FF);
    g_rf_chnlbw_val |= (1 << 10) | (1 << 11);

    g_rf_chnlbw_val &= ~(1u << 15);

    rtl_write_rf(dev_hdl, RF_CHNLBW, g_rf_chnlbw_val);

    rtl8188e_apply_tx_power_by_rate(dev_hdl);

    ESP_LOGD(TAG, "Tuned to channel %d (20 MHz)", channel);
}

