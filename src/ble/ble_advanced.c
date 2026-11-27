/**
 * @file ble_advanced.c
 * @brief Implementazione didattica delle tecniche descritte in "ESPwn32".
 *
 * Nota: i simboli esterni (p_rx_buffer, llc_env, btdm_r_ble_bt_handler_tab_p_get,
 * phy_get_romfuncs, ecc.) vengono risolti tramite i linker script della Mask ROM
 * specifici per la revisione del SoC (ESP32, ESP32-S3, ESP32-C3).
 */

#include "ble_advanced.h"
#include <string.h>
#include "esp_attr.h"
#include "freertos/FreeRTOS.h"
#include "freertos/portmacro.h"

/* ============================================================================
 * SIMBOLI ESTERNI IN MASK ROM E STRUTTURE EXCHANGE MEMORY
 * ============================================================================ */

#ifndef IDX_LLD_PDU_DATA_SEND
#define IDX_LLD_PDU_DATA_SEND       0
#endif

#ifndef IDX_LLD_PDU_DATA_TX_PUSH
#define IDX_LLD_PDU_DATA_TX_PUSH    1
#endif

#ifndef IDX_ROM_LOOPBACK_MODE_EN
#define IDX_ROM_LOOPBACK_MODE_EN    0
#endif

#define LLC_ENV_EVT_PTR_OFFSET      0x10U
#define LLD_EVT_TX_PROG_OFFSET      0x28U
#define BLE_EM_TEST_MODE_FLAG       (1U << 15)
#define BLE_EM_HOP_DISABLE_FLAG     (1U << 15)

struct co_list_hdr {
    struct co_list_hdr *next;
};

struct em_buf_node {
    struct co_list_hdr hdr;
    uint16_t idx;
    uint16_t buf_ptr;
};

struct em_desc_node {
    struct co_list_hdr hdr;
    uint8_t  llid;
    uint16_t length;
    uint16_t buffer_idx;
    uint16_t buffer_ptr;
};

struct hci_acl_data_tx {
    struct em_buf_node *buf;
    uint16_t length;
    uint8_t  pb_bc_flag;
};

struct lld_evt_tag {
    struct {
        int maxcnt;
    } tx_prog;
};

typedef int  (*lld_pdu_data_send_t)(struct hci_acl_data_tx *param);
typedef void (*lld_pdu_data_tx_push_t)(struct lld_evt_tag *env,
                                       struct em_desc_node *node,
                                       bool can_be_freed);
typedef void (*rom_loopback_mode_en_t)(int enable);

/* Simboli risolti dal linker script della Mask ROM */
extern uint8_t   *p_rx_buffer;
extern uintptr_t  llc_env[];
extern uint8_t   *em_ble_ch_freq_offset_tab; /* Tabella offset MHz da 2402 MHz (Sez. V-C.1) */

extern struct em_desc_node *em_buf_tx_desc_alloc(void);
extern void                 em_buf_tx_desc_free(struct em_desc_node *desc);
extern struct em_buf_node  *em_buf_tx_alloc(void);
extern void               **btdm_r_ble_bt_handler_tab_p_get(void);

/* Funzioni SDK / Mask ROM per calibrazione e controllo PHY (Sez. V-D) */
extern void   esp_bt_controller_shutdown(void);
extern void   esp_phy_erase_cal_data_in_nvs(void);
extern void   esp_phy_enable(void);
extern void **phy_get_romfuncs(void);
extern void   phy_dis_hw_set_freq(void);
extern void   set_chan_freq_sw_start(int offset_mhz_from_2400, int p1, int p2);
extern void   ram_start_tx_tone(int en, int p1, int amp, int p3, int p4, int p5);

/* Stato globale protetto da spinlock SMP */
static portMUX_TYPE           s_ble_mux                = portMUX_INITIALIZER_UNLOCKED;
static lld_pdu_data_send_t    pfn_lld_pdu_data_send    = NULL;
static lld_pdu_data_tx_push_t pfn_lld_pdu_data_tx_push = NULL;
static on_tx_pdu_cb_t         gpfn_on_tx_data_pdu      = NULL;
static bool                   s_ble_hooks_installed    = false;

static rom_loopback_mode_en_t pfn_rom_loopback_mode_en = NULL;
static volatile bool          s_divert_calibration     = false;

/* ============================================================================
 * 1. SEZIONE V-B: HOOKING TX E INIEZIONE PDU LINK LAYER (Listing 2 e 3)
 * ============================================================================ */

static int IRAM_ATTR _lld_pdu_data_send(struct hci_acl_data_tx *param)
{
    on_tx_pdu_cb_t cb = gpfn_on_tx_data_pdu;

    if (cb != NULL && param != NULL && param->buf != NULL && p_rx_buffer != NULL) {
        uint8_t *pdu_ptr = p_rx_buffer + param->buf->buf_ptr;
        if (cb(0, pdu_ptr, param->length) == HOOK_BLOCK) {
            /* Converte la PDU in Empty PDU per sopprimerla senza leak di buffer */
            param->length = 0;
        }
    }

    return pfn_lld_pdu_data_send(param);
}

esp_err_t ble_install_hooks(on_tx_pdu_cb_t tx_callback)
{
    void **rom_func_table = btdm_r_ble_bt_handler_tab_p_get();
    if (rom_func_table == NULL) {
        return ESP_ERR_NOT_FOUND;
    }

    portENTER_CRITICAL_SAFE(&s_ble_mux);

    if (s_ble_hooks_installed) {
        gpfn_on_tx_data_pdu = tx_callback;
        portEXIT_CRITICAL_SAFE(&s_ble_mux);
        return ESP_OK;
    }

    pfn_lld_pdu_data_send    = (lld_pdu_data_send_t)rom_func_table[IDX_LLD_PDU_DATA_SEND];
    pfn_lld_pdu_data_tx_push = (lld_pdu_data_tx_push_t)rom_func_table[IDX_LLD_PDU_DATA_TX_PUSH];
    gpfn_on_tx_data_pdu      = tx_callback;

    rom_func_table[IDX_LLD_PDU_DATA_SEND] = (void *)_lld_pdu_data_send;
    s_ble_hooks_installed = true;

    portEXIT_CRITICAL_SAFE(&s_ble_mux);
    return ESP_OK;
}

esp_err_t ble_uninstall_hooks(void)
{
    void **rom_func_table = btdm_r_ble_bt_handler_tab_p_get();
    if (rom_func_table == NULL) {
        return ESP_ERR_NOT_FOUND;
    }

    portENTER_CRITICAL_SAFE(&s_ble_mux);

    if (!s_ble_hooks_installed) {
        portEXIT_CRITICAL_SAFE(&s_ble_mux);
        return ESP_ERR_INVALID_STATE;
    }

    rom_func_table[IDX_LLD_PDU_DATA_SEND] = (void *)pfn_lld_pdu_data_send;
    gpfn_on_tx_data_pdu   = NULL;
    s_ble_hooks_installed = false;

    portEXIT_CRITICAL_SAFE(&s_ble_mux);
    return ESP_OK;
}

esp_err_t IRAM_ATTR ble_send_raw_pdu(int conhdl, uint8_t llid,
                                     const void *p_pdu, uint16_t length,
                                     bool can_be_freed)
{
    if (pfn_lld_pdu_data_tx_push == NULL || p_rx_buffer == NULL) {
        return ESP_ERR_INVALID_STATE;
    }
    if (conhdl < 0 || conhdl >= BLE_MAX_CONNECTIONS ||
        p_pdu == NULL || length == 0 || length > BLE_MAX_PDU_PAYLOAD_LEN ||
        llid == 0 || (llid & ~0x03U) != 0) {
        return ESP_ERR_INVALID_ARG;
    }

    uintptr_t conn_env = llc_env[conhdl];
    if (conn_env == 0) {
        return ESP_ERR_INVALID_STATE;
    }

    uintptr_t evt_base = *(uintptr_t *)(conn_env + LLC_ENV_EVT_PTR_OFFSET);
    if (evt_base == 0) {
        return ESP_ERR_INVALID_STATE;
    }

    struct lld_evt_tag *env = (struct lld_evt_tag *)(evt_base + LLD_EVT_TX_PROG_OFFSET);

    portENTER_CRITICAL_SAFE(&s_ble_mux);

    struct em_desc_node *data_send = em_buf_tx_desc_alloc();
    if (data_send == NULL) {
        portEXIT_CRITICAL_SAFE(&s_ble_mux);
        return ESP_ERR_NO_MEM;
    }

    struct em_buf_node *node = em_buf_tx_alloc();
    if (node == NULL) {
        em_buf_tx_desc_free(data_send);
        portEXIT_CRITICAL_SAFE(&s_ble_mux);
        return ESP_ERR_NO_MEM;
    }

    memcpy(p_rx_buffer + node->buf_ptr, p_pdu, length);

    data_send->llid       = llid;
    data_send->length     = length;
    data_send->buffer_idx = node->idx;
    data_send->buffer_ptr = node->buf_ptr;

    pfn_lld_pdu_data_tx_push(env, data_send, can_be_freed);
    env->tx_prog.maxcnt--;

    portEXIT_CRITICAL_SAFE(&s_ble_mux);
    return ESP_OK;
}

esp_err_t ble_send_ll_version_ind(int conhdl)
{
    const ble_ll_version_ind_t version_pdu = {
        .opcode      = LL_VERSION_IND_OP,
        .vers_nr     = 0x0C,
        .comp_id     = 0x0060,
        .sub_vers_nr = 0x0000
    };

    return ble_send_raw_pdu(conhdl, BLE_LLID_CONTROL,
                            &version_pdu, sizeof(version_pdu), true);
}

/* ============================================================================
 * 2. SEZIONE V-C.1: PRIMITIVE GFSK E RIMAPPATURA FREQUENZE (Listing 4)
 * ============================================================================ */

esp_err_t ble_set_custom_freq_mhz(uint8_t ble_channel, uint16_t target_freq_mhz)
{
    if (em_ble_ch_freq_offset_tab == NULL) {
        return ESP_ERR_INVALID_STATE;
    }
    if (ble_channel > 39U || target_freq_mhz < 2402U || target_freq_mhz > 2480U) {
        return ESP_ERR_INVALID_ARG;
    }

    /* La tabella in Exchange Memory mappa ogni canale BLE a un offset in MHz da 2402 MHz */
    em_ble_ch_freq_offset_tab[ble_channel] = (uint8_t)(target_freq_mhz - 2402U);
    return ESP_OK;
}

esp_err_t ble_config_raw_gfsk(struct em_ble_cntl_struct *cntl,
                              const gfsk_raw_config_t *cfg)
{
    if (cntl == NULL || cfg == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (cfg->use_2mbps && !BLE_SUPPORTS_LE_2M) {
        return ESP_ERR_NOT_SUPPORTED;
    }

    esp_err_t err = ble_set_custom_freq_mhz(cfg->ble_channel_slot, cfg->freq_mhz);
    if (err != ESP_OK) {
        return err;
    }

    portENTER_CRITICAL_SAFE(&s_ble_mux);

    /* 1. Forzatura Test Mode per bypassare la validazione formato frame BLE */
    cntl->cntl |= BLE_EM_TEST_MODE_FLAG;

    /* 2. Impostazione Sync Word arbitraria a 32 bit */
    cntl->syncl = (uint16_t)(cfg->sync_word & 0xFFFFU);
    cntl->syncw = (uint16_t)((cfg->sync_word >> 16) & 0xFFFFU);

    /* 3. Disabilitazione channel hopping e selezione canale rimappato */
    cntl->hopcntl = (uint16_t)(BLE_EM_HOP_DISABLE_FLAG | (cfg->ble_channel_slot & 0x3FU));

    /* 4. Estensione buffer di ricezione fino al massimo consentito (255 byte) */
    cntl->rxmaxbuf = 255U;

#if BLE_SUPPORTS_LE_2M
    /* 5. Selezione data rate 1 Mbps (0) o 2 Mbps (1) su ESP32-S3 / ESP32-C3 */
    if (cfg->use_2mbps) {
        cntl->thrcntl_ratecntl |= 0x0001U;
    } else {
        cntl->thrcntl_ratecntl &= ~0x0001U;
    }
#endif

    /* 6. Configurazione registro hardware BLE_RWBLECNTL_REG */
    uint32_t hw_reg = BLE_RWBLECNTL_REG;
    hw_reg &= ~BLE_RWBLECNTL_SYNCERR_MASK;
    hw_reg |= ((uint32_t)(cfg->sync_err_bits & 0x07U) << BLE_RWBLECNTL_SYNCERR_SHIFT);

    if (cfg->disable_crc) {
        hw_reg |= BLE_RWBLECNTL_CRC_DIS;
    } else {
        hw_reg &= ~BLE_RWBLECNTL_CRC_DIS;
    }

    if (cfg->disable_whitening) {
        hw_reg |= BLE_RWBLECNTL_WHITENING_DIS;
    } else {
        hw_reg &= ~BLE_RWBLECNTL_WHITENING_DIS;
    }

    BLE_RWBLECNTL_REG = hw_reg;

    portEXIT_CRITICAL_SAFE(&s_ble_mux);
    return ESP_OK;
}

/* ============================================================================
 * 3. SEZIONE V-C.2: ALGORITMI NETWORK KEY ANT E FRAMING (Appendici A e B)
 * ============================================================================ */

static const uint8_t s_ant_val_xor[8]  = {0x20, 0x1A, 0x47, 0x11, 0x50, 0x93, 0x36, 0x8F};
static const uint8_t s_ant_val_and[8]  = {0xEC, 0x3F, 0xD7, 0xDB, 0x79, 0xF7, 0xBE, 0xEF};
static const uint8_t s_ant_pre_xkey[8] = {0xFE, 0xFF, 0x1C, 0x7C, 0xFC, 0x0C, 0x04, 0x3C};
static const uint8_t s_ant_pre_and[8]  = {0x41, 0x10, 0x28, 0x86, 0x08, 0xC0, 0x13, 0x24};

bool ant_is_valid_key(const uint8_t key[8])
{
    uint8_t k_deriv = 0;
    uint8_t nb_xor  = 1;

    for (uint8_t i = 0; i < 8; ++i) {
        uint8_t tmp = 0;
        for (uint8_t j = 0; j < nb_xor; ++j) {
            if (j < 6) {
                tmp ^= key[2U + j];
            } else if (j == 6) {
                tmp ^= key[1];
            } else {
                tmp ^= key[0];
            }
        }
        tmp &= s_ant_val_and[i];
        tmp ^= s_ant_val_xor[i];
        k_deriv |= tmp;
        ++nb_xor;
    }

    return (k_deriv == 0);
}

uint16_t ant_gen_key_preamble(const uint8_t key[8])
{
    uint8_t low  = 0;
    uint8_t high = 0;
    uint8_t acc  = 0;

    for (uint8_t i = 0; i < 8; ++i) {
        if (i == 4) {
            low = acc;
            acc = 0;
        }
        uint8_t tmp = 0;
        for (uint8_t j = 0; j < 8; ++j) {
            if (s_ant_pre_xkey[i] & (1U << j)) {
                tmp ^= key[j];
            }
        }
        tmp &= s_ant_pre_and[i];
        acc |= tmp;
    }
    high = acc;

    return (uint16_t)(((uint16_t)high << 8) | low);
}

uint32_t ant_build_sniff_syncword(uint16_t preamble, uint16_t device_number)
{
    /* Concatena il preambolo a 2 byte (es. 0xA6C5) con il Device Number del target */
    return ((uint32_t)preamble << 16) | (uint32_t)device_number;
}

static uint16_t ant_crc16_ccitt(const uint8_t *data, size_t len)
{
    uint16_t crc = 0xFFFFU;
    for (size_t i = 0; i < len; ++i) {
        crc ^= (uint16_t)data[i] << 8;
        for (int b = 0; b < 8; ++b) {
            crc = (crc & 0x8000U) ? ((crc << 1) ^ 0x1021U) : (crc << 1);
        }
    }
    return crc;
}

void ant_prepare_tx_packet(ant_packet_t *pkt, uint16_t preamble,
                           uint16_t dev_num, uint8_t dev_type,
                           uint8_t trans_type, uint8_t header,
                           const uint8_t payload[7])
{
    if (pkt == NULL) {
        return;
    }

    /* Conversione da Little Endian (ESP32) a Big Endian (ANT over-the-air) */
    pkt->preamble      = __builtin_bswap16(preamble);
    pkt->device_number = __builtin_bswap16(dev_num);
    pkt->device_type   = dev_type;
    pkt->trans_type    = trans_type;
    pkt->header        = header;
    memcpy(pkt->payload, payload, 7U);

    uint16_t crc = ant_crc16_ccitt((const uint8_t *)pkt, offsetof(ant_packet_t, crc16));
    pkt->crc16 = __builtin_bswap16(crc);
}

/* ============================================================================
 * 4. SEZIONE V-C.3 & V-C.4: RIITEK (Appendice C) E WAZABEE (802.15.4 -> GFSK)
 * ============================================================================ */

uint16_t riitek_crc16(const uint8_t *data, size_t len)
{
    /* Polinomio 0x1021 e valore iniziale 0x8B83 (Appendice C-B) */
    uint16_t crc = 0x8B83U;
    for (size_t i = 0; i < len; ++i) {
        crc ^= (uint16_t)data[i] << 8;
        for (int b = 0; b < 8; ++b) {
            crc = (crc & 0x8000U) ? ((crc << 1) ^ 0x1021U) : (crc << 1);
        }
    }
    return crc;
}

uint16_t wazabee_map_nibble_to_gfsk(uint8_t ieee802154_nibble)
{
    /*
     * Sezione V-C.4: su ESP32-S3 ed ESP32-C3 (PHY LE 2M a 2 Mbps), ogni simbolo
     * O-QPSK a 4 bit (chip sequence da 32 chip @ 2 Mchip/s) viene approssimato
     * tramite una sequenza binaria equivalente trasmessa in modulazione GFSK 2 Mbps.
     */
    static const uint16_t s_oqpsk_to_gfsk_lut[16] = {
        0x744A, 0xB474, 0x4B47, 0x74B4, 0x474B, 0xB474, 0x4B47, 0x74B4,
        0x8BB5, 0x4B8B, 0xB4B8, 0x8B4B, 0xB8B4, 0x4B8B, 0xB4B8, 0x8B4B
    };
    return s_oqpsk_to_gfsk_lut[ieee802154_nibble & 0x0FU];
}

/* ============================================================================
 * 5. SEZIONE V-D: DEVIAZIONE CALIBRAZIONE RF E CONTROLLO TRANSCEIVER (List. 6–7)
 * ============================================================================ */

static void IRAM_ATTR _rom_loopback_mode_en(int enable)
{
    if (s_divert_calibration && enable != 0) {
        /*
         * Sezione V-D.3: impedendo l'abilitazione del loopback interno TX->RX
         * durante la calibrazione I/Q, il segnale di calibrazione viene irradiato
         * direttamente verso l'antenna anziché restare confinato nel frontend RF.
         */
        return;
    }

    if (pfn_rom_loopback_mode_en != NULL) {
        pfn_rom_loopback_mode_en(enable);
    }
}

esp_err_t rf_install_calibration_diversion(void)
{
    void **phy_rom_table = phy_get_romfuncs();
    if (phy_rom_table == NULL) {
        return ESP_ERR_NOT_FOUND;
    }

    portENTER_CRITICAL_SAFE(&s_ble_mux);
    if (pfn_rom_loopback_mode_en == NULL) {
        pfn_rom_loopback_mode_en =
            (rom_loopback_mode_en_t)phy_rom_table[IDX_ROM_LOOPBACK_MODE_EN];
        phy_rom_table[IDX_ROM_LOOPBACK_MODE_EN] = (void *)_rom_loopback_mode_en;
    }
    s_divert_calibration = true;
    portEXIT_CRITICAL_SAFE(&s_ble_mux);

    return ESP_OK;
}

esp_err_t rf_force_full_calibration(void)
{
    /* Listing 6: forza una calibrazione completa cancellando i dati salvati in NVS */
    esp_bt_controller_shutdown();
    esp_phy_erase_cal_data_in_nvs();
    esp_phy_enable();
    return ESP_OK;
}

void IRAM_ATTR rf_set_frequency_mhz(uint16_t freq_mhz)
{
    if (freq_mhz < 2400U || freq_mhz > 2483U) {
        return;
    }

    /* Sezione V-D.3a: disabilita il controllo hardware PLL e imposta offset da 2400 MHz */
    phy_dis_hw_set_freq();
    set_chan_freq_sw_start((int)(freq_mhz - 2400U), 0, 0);
}

void IRAM_ATTR rf_emit_tone(uint8_t mode, uint8_t amplitude)
{
    /* Genera un tono continuo o un segnale glitched (Appendice D) */
    ram_start_tx_tone((int)mode, 0, (int)amplitude, 0, 0, 0);
}

void IRAM_ATTR rf_sweep_adv_channels(volatile const bool *active_flag)
{
    if (active_flag == NULL) {
        return;
    }

    /* Listing 7: commutazione rapida (~83 us) sui 3 canali di advertising BLE */
    while (*active_flag) {
        set_chan_freq_sw_start(2, 0, 0);   /* Canale 37: 2402 MHz */
        ram_start_tx_tone(1, 0, 10, 0, 0, 0);

        set_chan_freq_sw_start(26, 0, 0);  /* Canale 38: 2426 MHz */
        ram_start_tx_tone(1, 0, 10, 0, 0, 0);

        set_chan_freq_sw_start(80, 0, 0);  /* Canale 39: 2480 MHz */
        ram_start_tx_tone(1, 0, 10, 0, 0, 0);
    }
}