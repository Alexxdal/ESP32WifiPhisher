/**
 * @file espwn32_protocols.c
 * @brief Implementazione unificata per sniffing e framing ANT+ e Riitek Rii i8
 *        tramite le primitive GFSK di ble_advanced.
 */

#include "espwn32_protocols.h"
#include <string.h>
#include <stdio.h>
#include "esp_attr.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"

/* Simboli esterni già risolti dal linker script della Mask ROM */
extern uint8_t  *p_rx_buffer;
extern void    **btdm_r_ble_bt_handler_tab_p_get(void);

/* Descrittore RX nella Exchange Memory */
struct em_rx_desc {
    uint16_t next_ptr;
    uint16_t rxstatus;
    uint16_t rxheader;   /* Bit [15:8]: lunghezza payload ricevuto */
    uint16_t rxdataptr;  /* Offset rispetto a p_rx_buffer */
};

typedef void (*lld_scan_start_t)(struct em_ble_cntl_struct *cntl);
typedef void (*lld_rx_handler_t)(struct em_rx_desc *desc);

#define MAX_CAPTURED_FRAME_LEN  32U
#define SNIFFER_QUEUE_DEPTH     24U

typedef struct {
    espwn32_proto_mode_t mode;
    uint16_t             locked_ant_dev;
    uint8_t              len;
    uint8_t              data[MAX_CAPTURED_FRAME_LEN];
} captured_packet_t;

static lld_scan_start_t              pfn_orig_scan_start = NULL;
static lld_rx_handler_t              pfn_orig_rx_handler = NULL;
static QueueHandle_t                 s_rx_queue          = NULL;
static TaskHandle_t                  s_decoder_task      = NULL;
static struct em_ble_cntl_struct    *s_active_cntl       = NULL;

static volatile espwn32_proto_mode_t s_current_mode      = PROTO_MODE_DISABLED;
static volatile uint16_t             s_target_ant_dev    = 0;
static volatile bool                 s_auto_lock_ant     = false;
static gfsk_raw_config_t             s_gfsk_cfg          = {0};

/* ============================================================================
 * 1. CONFIGURAZIONE REGISTRI GFSK TRAMITE ble_config_raw_gfsk()
 * ============================================================================ */

static esp_err_t apply_active_gfsk_profile(struct em_ble_cntl_struct *cntl)
{
    if (cntl == NULL || s_current_mode == PROTO_MODE_DISABLED) {
        return ESP_ERR_INVALID_STATE;
    }
    /* Riusa direttamente la primitiva di ble_advanced.c */
    return ble_config_raw_gfsk(cntl, &s_gfsk_cfg);
}

esp_err_t proto_configure_ant_scan(bool auto_lock_first_device)
{
    s_auto_lock_ant  = auto_lock_first_device;
    s_target_ant_dev = 0;
    s_current_mode   = PROTO_MODE_ANT_SCAN;

    /* Sez. V-C.2.d: canale 2457 MHz, sync word 0xAAAAA6C5 (0xAAAA + preambolo ANT+) */
    s_gfsk_cfg = (gfsk_raw_config_t){
        .sync_word         = ANT_PLUS_SCAN_SYNCWORD,
        .freq_mhz          = ANT_PLUS_FREQ_MHZ,
        .ble_channel_slot  = 0,
        .sync_err_bits     = 1,
        .use_2mbps         = false, /* ANT+ opera a 1 Mbps */
        .disable_crc       = true,
        .disable_whitening = true
    };

    if (s_active_cntl != NULL) {
        return apply_active_gfsk_profile(s_active_cntl);
    }
    return ESP_OK;
}

esp_err_t proto_configure_ant_sniff(uint16_t target_device_number)
{
    s_target_ant_dev = target_device_number;
    s_current_mode   = PROTO_MODE_ANT_SNIFF;

    /* Sez. V-C.2.d: concatena 0xA6C5 con il Device Number del sensore bersaglio */
    s_gfsk_cfg = (gfsk_raw_config_t){
        .sync_word         = ant_build_sniff_syncword(ANT_PLUS_PREAMBLE, target_device_number),
        .freq_mhz          = ANT_PLUS_FREQ_MHZ,
        .ble_channel_slot  = 0,
        .sync_err_bits     = 1,
        .use_2mbps         = false,
        .disable_crc       = true,
        .disable_whitening = true
    };

    if (s_active_cntl != NULL) {
        return apply_active_gfsk_profile(s_active_cntl);
    }
    return ESP_OK;
}

esp_err_t proto_configure_riitek(void)
{
    s_current_mode = PROTO_MODE_RIITEK;

    /* Sez. V-C.3.b e App. C: canale 2426 MHz, preambolo fisso 0x000000AA */
    s_gfsk_cfg = (gfsk_raw_config_t){
        .sync_word         = RIITEK_PREAMBLE,
        .freq_mhz          = RIITEK_FREQ_MHZ,
        .ble_channel_slot  = 0,
        .sync_err_bits     = 2,
        .use_2mbps         = false, /* Riitek opera a 1 Mbps */
        .disable_crc       = true,
        .disable_whitening = true
    };

    if (s_active_cntl != NULL) {
        return apply_active_gfsk_profile(s_active_cntl);
    }
    return ESP_OK;
}

/* ============================================================================
 * 2. HOOK DI AVVIO SCAN E CATTURA RX IN IRAM
 * ============================================================================ */

static void IRAM_ATTR _proto_hook_scan_start(struct em_ble_cntl_struct *cntl)
{
    s_active_cntl = cntl;

    if (s_current_mode != PROTO_MODE_DISABLED) {
        apply_active_gfsk_profile(cntl);
    }

    pfn_orig_scan_start(cntl);
}

static void IRAM_ATTR _proto_hook_rx_handler(struct em_rx_desc *desc)
{
    espwn32_proto_mode_t mode = s_current_mode;

    if (mode != PROTO_MODE_DISABLED && desc != NULL &&
        p_rx_buffer != NULL && s_rx_queue != NULL) {

        uint8_t rx_len = (uint8_t)((desc->rxheader >> 8) & 0xFFU);

        if (rx_len > 0 && rx_len <= MAX_CAPTURED_FRAME_LEN) {
            captured_packet_t cap = {
                .mode           = mode,
                .locked_ant_dev = s_target_ant_dev,
                .len            = rx_len
            };
            memcpy(cap.data, p_rx_buffer + desc->rxdataptr, rx_len);

            BaseType_t woken = pdFALSE;
            xQueueSendFromISR(s_rx_queue, &cap, &woken);

            /* Azzera la lunghezza per impedire allo stack BLE di parsare il frame */
            desc->rxheader &= 0x00FFU;
        }
    }

    pfn_orig_rx_handler(desc);
}

/* ============================================================================
 * 3. DECODIFICA DEI PACCHETTI CATTURATI (ANT+ e RIITEK)
 * ============================================================================ */

static uint16_t ant_crc16_ccitt_check(const uint8_t *data, size_t len)
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

static void decode_ant_packet(const captured_packet_t *cap)
{
    ant_packet_t pkt = {0};

    if (cap->mode == PROTO_MODE_ANT_SCAN) {
        /*
         * L'hardware ha consumato i 4 byte di sync (0xAAAA + 0xA6C5):
         * in memoria restano i 14 byte a partire da device_number.
         */
        const size_t rem_len = sizeof(ant_packet_t) - offsetof(ant_packet_t, device_number);
        if (cap->len < rem_len) {
            return;
        }
        pkt.preamble = __builtin_bswap16(ANT_PLUS_PREAMBLE);
        memcpy(&pkt.device_number, cap->data, rem_len);
    } else {
        /*
         * In modalità ANT_SNIFF l'hardware ha consumato 0xA6C5 + device_number:
         * in memoria restano i 12 byte a partire da device_type.
         */
        const size_t rem_len = sizeof(ant_packet_t) - offsetof(ant_packet_t, device_type);
        if (cap->len < rem_len) {
            return;
        }
        pkt.preamble      = __builtin_bswap16(ANT_PLUS_PREAMBLE);
        pkt.device_number = __builtin_bswap16(cap->locked_ant_dev);
        memcpy(&pkt.device_type, cap->data, rem_len);
    }

    /* Verifica CRC-16 CCITT su tutto il pacchetto escluso il campo crc16 finale */
    uint16_t calc_crc = ant_crc16_ccitt_check((const uint8_t *)&pkt,
                                              offsetof(ant_packet_t, crc16));
    uint16_t recv_crc = __builtin_bswap16(pkt.crc16);
    if (calc_crc != recv_crc) {
        return;
    }

    uint16_t dev_num = __builtin_bswap16(pkt.device_number);

    printf("[ANT+] DevNum: 0x%04X | Type: 0x%02X | Hdr: 0x%02X | Payload: "
           "%02X %02X %02X %02X %02X %02X %02X\n",
           dev_num, pkt.device_type, pkt.header,
           pkt.payload[0], pkt.payload[1], pkt.payload[2], pkt.payload[3],
           pkt.payload[4], pkt.payload[5], pkt.payload[6]);

    /* Se siamo in fase 1 (SCAN) e auto-lock è attivo, aggancia subito il sensore */
    if (cap->mode == PROTO_MODE_ANT_SCAN && s_auto_lock_ant) {
        printf("[ANT+] Aggancio automatico al dispositivo 0x%04X...\n", dev_num);
        proto_configure_ant_sniff(dev_num);
    }
}

static void decode_riitek_packet(const captured_packet_t *cap)
{
    /*
     * L'hardware ha consumato i 4 byte di preamble (0x000000AA):
     * i byte ricevuti corrispondono a riitek_frame_t a partire da address[0].
     */
    const size_t body_len = sizeof(riitek_frame_t) - offsetof(riitek_frame_t, address);
    if (cap->len < body_len) {
        return;
    }

    riitek_frame_t frame = {0};
    frame.preamble = RIITEK_PREAMBLE;
    memcpy(frame.address, cap->data, body_len);

    /* Riusa riitek_crc16() di ble_advanced.h su address + seq_and_flags + frame_type + payload */
    const size_t crc_span = offsetof(riitek_frame_t, crc16) - offsetof(riitek_frame_t, address);
    uint16_t calc_crc = riitek_crc16(frame.address, crc_span);
    uint16_t recv_crc = __builtin_bswap16(frame.crc16);

    if (calc_crc != recv_crc) {
        return;
    }

    printf("[RIITEK %02X:%02X:%02X:%02X:%02X] ",
           frame.address[0], frame.address[1], frame.address[2],
           frame.address[3], frame.address[4]);

    if (frame.frame_type == RIITEK_FRAME_KEYBOARD) {
        printf("KEY -> Mod: 0x%02X, Keycode: 0x%02X\n",
               frame.payload[0], frame.payload[2]);
    } else if (frame.frame_type == RIITEK_FRAME_MOUSE) {
        int16_t dx = (int16_t)(frame.payload[1] | ((uint16_t)frame.payload[2] << 8));
        int16_t dy = (int16_t)(frame.payload[3] | ((uint16_t)frame.payload[4] << 8));
        printf("MOUSE -> Btn: 0x%02X, dX: %d, dY: %d\n",
               frame.payload[0], dx, dy);
    }
}

static void proto_decoder_task(void *arg)
{
    (void)arg;
    captured_packet_t cap;

    while (1) {
        if (xQueueReceive(s_rx_queue, &cap, portMAX_DELAY) == pdTRUE) {
            if (cap.mode == PROTO_MODE_ANT_SCAN || cap.mode == PROTO_MODE_ANT_SNIFF) {
                decode_ant_packet(&cap);
            } else if (cap.mode == PROTO_MODE_RIITEK) {
                decode_riitek_packet(&cap);
            }
        }
    }
}

/* ============================================================================
 * 4. INIZIALIZZAZIONE E SUPPORTO PACKET-IN-PACKET TX (Sezione V-C.1)
 * ============================================================================ */

esp_err_t proto_sniffer_init(uint8_t idx_scan_start, uint8_t idx_rx_handler)
{
    void **rom_tab = btdm_r_ble_bt_handler_tab_p_get();
    if (rom_tab == NULL) {
        return ESP_ERR_NOT_FOUND;
    }

    if (s_rx_queue == NULL) {
        s_rx_queue = xQueueCreate(SNIFFER_QUEUE_DEPTH, sizeof(captured_packet_t));
        if (s_rx_queue == NULL) {
            return ESP_ERR_NO_MEM;
        }
    }

    if (s_decoder_task == NULL) {
        if (xTaskCreate(proto_decoder_task, "proto_dec", 3072, NULL, 5, &s_decoder_task) != pdPASS) {
            return ESP_ERR_NO_MEM;
        }
    }

    if (pfn_orig_scan_start == NULL) {
        pfn_orig_scan_start = (lld_scan_start_t)rom_tab[idx_scan_start];
        rom_tab[idx_scan_start] = (void *)_proto_hook_scan_start;
    }

    if (pfn_orig_rx_handler == NULL) {
        pfn_orig_rx_handler = (lld_rx_handler_t)rom_tab[idx_rx_handler];
        rom_tab[idx_rx_handler] = (void *)_proto_hook_rx_handler;
    }

    return ESP_OK;
}

void proto_sniffer_deinit(uint8_t idx_scan_start, uint8_t idx_rx_handler)
{
    void **rom_tab = btdm_r_ble_bt_handler_tab_p_get();
    s_current_mode = PROTO_MODE_DISABLED;

    if (rom_tab != NULL) {
        if (pfn_orig_scan_start != NULL) {
            rom_tab[idx_scan_start] = (void *)pfn_orig_scan_start;
            pfn_orig_scan_start = NULL;
        }
        if (pfn_orig_rx_handler != NULL) {
            rom_tab[idx_rx_handler] = (void *)pfn_orig_rx_handler;
            pfn_orig_rx_handler = NULL;
        }
    }

    if (s_decoder_task != NULL) {
        vTaskDelete(s_decoder_task);
        s_decoder_task = NULL;
    }

    if (s_rx_queue != NULL) {
        vQueueDelete(s_rx_queue);
        s_rx_queue = NULL;
    }
}

size_t proto_wrap_packet_in_packet(uint8_t *out_buf, size_t out_max,
                                   const void *inner_frame, size_t inner_len)
{
    /*
     * Sezione V-C.1: nella strategia packet-in-packet, l'intero pacchetto
     * proprietario (completo di preambolo, indirizzo, payload e CRC) viene
     * inserito come payload di un pacchetto inviato con whitening disabilitato:
     * il ricevitore target ignora l'intestazione esterna e sincronizza il proprio
     * demodulatore direttamente sul preambolo interno.
     */
    const uint8_t preamble_padding[2] = {0xAA, 0xAA};
    const size_t total_len = sizeof(preamble_padding) + inner_len;

    if (out_buf == NULL || inner_frame == NULL || inner_len == 0 || total_len > out_max) {
        return 0;
    }

    memcpy(out_buf, preamble_padding, sizeof(preamble_padding));
    memcpy(out_buf + sizeof(preamble_padding), inner_frame, inner_len);
    return total_len;
}