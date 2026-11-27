/**
 * @file espwn32_full_study.h
 * @brief Mappatura completa delle primitive descritte nel paper "ESPwn32"
 *        (Sezioni IV, V-A, V-B, V-C, V-D e Appendici A-D).
 */

#ifndef ESPWN32_FULL_STUDY_H
#define ESPWN32_FULL_STUDY_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * SEZIONE III & IV: INDIRIZZI HARDWARE E REGISTRI DEL CONTROLLER BLE
 * ============================================================================ */

#if CONFIG_IDF_TARGET_ESP32
    /* ESP32 (Xtensa LX6): solo PHY LE 1M (1 Mbps) */
    #define BLE_HW_BASE_ADDR        0x3FF71200UL
    #define BLE_SUPPORTS_LE_2M      0
#elif CONFIG_IDF_TARGET_ESP32S3 || CONFIG_IDF_TARGET_ESP32C3
    /* ESP32-S3 (Xtensa LX7) / ESP32-C3 (RISC-V): PHY LE 1M e LE 2M */
    #define BLE_HW_BASE_ADDR        0x60031000UL
    #define BLE_SUPPORTS_LE_2M      1
#else
    #define BLE_HW_BASE_ADDR        0x3FF71200UL
    #define BLE_SUPPORTS_LE_2M      0
#endif

/* Registro globale BLE_RWBLECNTL_REG (Sezione V-C.1) */
#define BLE_RWBLECNTL_REG           (*(volatile uint32_t *)(BLE_HW_BASE_ADDR + 0x00U))
#define BLE_RWBLECNTL_WHITENING_DIS (1U << 8)   /* Disabilita (de)whitening hardware */
#define BLE_RWBLECNTL_CRC_DIS       (1U << 9)   /* Disabilita verifica/calcolo CRC */
#define BLE_RWBLECNTL_SYNCERR_SHIFT 16U         /* Tolleranza bit-flip nella sync word */
#define BLE_RWBLECNTL_SYNCERR_MASK  (0x07U << BLE_RWBLECNTL_SYNCERR_SHIFT)

/* ============================================================================
 * SEZIONE V-B: MANIPOLAZIONE LINK LAYER BLE (Listing 2 e 3)
 * ============================================================================ */

#define HOOK_FORWARD                0
#define HOOK_BLOCK                  1

#define BLE_LLID_DATA_CONT          0x01U
#define BLE_LLID_DATA_START         0x02U
#define BLE_LLID_CONTROL            0x03U
#define LL_VERSION_IND_OP           0x0CU

#define BLE_MAX_PDU_PAYLOAD_LEN     251U
#define BLE_MAX_CONNECTIONS         3

typedef struct __attribute__((packed)) {
    uint8_t  opcode;      /* 0x0C */
    uint8_t  vers_nr;     /* Es. 0x0C = Core 5.3 */
    uint16_t comp_id;     /* Company ID (little-endian) */
    uint16_t sub_vers_nr; /* Subversione firmware */
} ble_ll_version_ind_t;

typedef int (*on_tx_pdu_cb_t)(int conhdl, uint8_t *pdu, uint16_t length);

esp_err_t ble_install_hooks(on_tx_pdu_cb_t tx_callback);
esp_err_t ble_uninstall_hooks(void);
esp_err_t ble_send_raw_pdu(int conhdl, uint8_t llid,
                           const void *p_pdu, uint16_t length,
                           bool can_be_freed);
esp_err_t ble_send_ll_version_ind(int conhdl);

/* ============================================================================
 * SEZIONE V-C.1: PRIMITIVE GFSK GENERICHE E EXCHANGE MEMORY (Listing 4)
 * ============================================================================ */

/* Struttura di controllo nella Exchange Memory (offset da Listing 4) */
struct __attribute__((packed)) em_ble_cntl_struct {
    uint16_t cntl;              /* 0x00: Formato pacchetto (Test Mode disabilita check BLE) */
    uint16_t reserved_02;       /* 0x02 */
    uint16_t thrcntl_ratecntl;  /* 0x04: Data rate 1Mbps / 2Mbps (solo S3/C3) */
    uint16_t reserved_06[3];    /* 0x06..0x0A */
    uint16_t syncl;             /* 0x0C: Access Address / Sync Word (16 bit bassi) */
    uint16_t syncw;             /* 0x0E: Access Address / Sync Word (16 bit alti) */
    uint16_t crcinit0;          /* 0x10: Valore iniziale CRC (16 bit bassi) */
    uint16_t crcinit1;          /* 0x12: Valore iniziale CRC (8 bit alti) */
    uint16_t filtpol_ralcntl;   /* 0x14: Policy di filtraggio indirizzi */
    uint16_t hopcntl;           /* 0x16: Controllo channel hopping e canale BLE */
    uint16_t txrxcntl;          /* 0x18: Controllo potenza TX / guadagno RX */
    uint16_t rxwincntl;         /* 0x1A: Finestra di ricezione */
    uint16_t txdescptr;         /* 0x1C: Puntatore al descrittore TX */
    uint16_t reserved_1e[2];    /* 0x1E..0x20 */
    uint16_t llchmap0;          /* 0x22: Channel map [15:0] */
    uint16_t llchmap1;          /* 0x24: Channel map [31:16] */
    uint16_t chmap2;            /* 0x26: Channel map [36:32] */
    uint16_t rxmaxbuf;          /* 0x28: Dimensione massima buffer RX (fino a 255 byte) */
};

typedef struct {
    uint32_t sync_word;         /* Pattern di sincronizzazione a 32 bit */
    uint16_t freq_mhz;          /* Frequenza centrale desiderata (es. 2457 MHz) */
    uint8_t  ble_channel_slot;  /* Canale BLE usato come slot di rimappatura (0..39) */
    uint8_t  sync_err_bits;     /* Bit-flip tollerati nella sync word (0..7) */
    bool     use_2mbps;         /* true = 2 Mbps (solo S3/C3), false = 1 Mbps */
    bool     disable_crc;       /* true = disabilita controllo CRC hardware */
    bool     disable_whitening; /* true = disabilita dewhitening hardware */
} gfsk_raw_config_t;

esp_err_t ble_set_custom_freq_mhz(uint8_t ble_channel, uint16_t target_freq_mhz);
esp_err_t ble_config_raw_gfsk(struct em_ble_cntl_struct *cntl,
                              const gfsk_raw_config_t *cfg);

/* ============================================================================
 * SEZIONE V-C.2: PROTOCOLLO ANT / ANT+ (Listing 5, Appendici A e B)
 * ============================================================================ */

#define ANT_PLUS_FREQ_MHZ           2457U
#define ANT_PLUS_PREAMBLE           0xA6C5U
#define ANT_PLUS_SCAN_SYNCWORD      0xAAAAA6C5UL /* 0xAAAA + 0xA6C5 */

/* Formato pacchetto ANT a lunghezza fissa di 16 byte (Listing 5) */
typedef struct __attribute__((packed)) {
    uint16_t preamble;          /* 2 byte: derivati dalla Network Key (0xA6C5 per ANT+) */
    uint16_t device_number;     /* 2 byte: identificativo univoco del sensore */
    uint8_t  device_type;       /* 1 byte: profilo dispositivo (es. HRM, cadenza) */
    uint8_t  trans_type;        /* 1 byte: caratteristiche canale */
    uint8_t  header;            /* 1 byte: tipo messaggio (broadcast/ack) */
    uint8_t  payload[7];        /* 7 byte: dati applicativi */
    uint16_t crc16;             /* 2 byte: CRC-16 CCITT */
} ant_packet_t;

bool     ant_is_valid_key(const uint8_t key[8]);
uint16_t ant_gen_key_preamble(const uint8_t key[8]);
uint32_t ant_build_sniff_syncword(uint16_t preamble, uint16_t device_number);
void     ant_prepare_tx_packet(ant_packet_t *pkt, uint16_t preamble,
                               uint16_t dev_num, uint8_t dev_type,
                               uint8_t trans_type, uint8_t header,
                               const uint8_t payload[7]);

/* ============================================================================
 * SEZIONE V-C.3 & V-C.4: RIITEK RII I8 (Appendice C) E 802.15.4 (WazaBee)
 * ============================================================================ */

#define RIITEK_FREQ_MHZ             2426U
#define RIITEK_PREAMBLE             0x000000AAUL
#define RIITEK_FRAME_MOUSE          0x04U
#define RIITEK_FRAME_KEYBOARD       0x0BU

typedef struct __attribute__((packed)) {
    uint32_t preamble;          /* 0x000000AA */
    uint8_t  address[5];        /* Indirizzo dispositivo a 5 byte */
    uint8_t  seq_and_flags;     /* 4 bit unknown + 4 bit sequence number */
    uint8_t  frame_type;        /* 0x04 (mouse) o 0x0B (tastiera) */
    uint8_t  payload[7];        /* Dati HID */
    uint16_t crc16;             /* Polinomio 0x1021, init 0x8B83 */
} riitek_frame_t;

uint16_t riitek_crc16(const uint8_t *data, size_t len);
uint16_t wazabee_map_nibble_to_gfsk(uint8_t ieee802154_nibble);

/* ============================================================================
 * SEZIONE V-D: DEVIAZIONE CALIBRAZIONE RF E CONTROLLO TRANSCEIVER (List. 6–7)
 * ============================================================================ */

esp_err_t rf_force_full_calibration(void);
esp_err_t rf_install_calibration_diversion(void);
void      rf_set_frequency_mhz(uint16_t freq_mhz);
void      rf_emit_tone(uint8_t mode, uint8_t amplitude);
void      rf_sweep_adv_channels(volatile const bool *active_flag);

#ifdef __cplusplus
}
#endif

#endif /* ESPWN32_FULL_STUDY_H */