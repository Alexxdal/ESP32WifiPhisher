/**
 * @file espwn32_protocols.h
 * @brief Modulo cross-protocol (ANT/ANT+ e Riitek Rii i8) basato su ble_advanced.
 *        Implementa le Sezioni V-C.1, V-C.2, V-C.3 e le Appendici A-C di "ESPwn32".
 */

#ifndef ESPWN32_PROTOCOLS_H
#define ESPWN32_PROTOCOLS_H

#include "ble_advanced.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    PROTO_MODE_DISABLED = 0,
    PROTO_MODE_ANT_SCAN,    /* Fase 1 ANT+: sync 0xAAAAA6C5 su 2457 MHz per scoprire Device Number */
    PROTO_MODE_ANT_SNIFF,   /* Fase 2 ANT+: sync 0xA6C5 + Device Number su 2457 MHz */
    PROTO_MODE_RIITEK       /* Sniffing tastiera/mouse Rii i8: sync 0x000000AA su 2426 MHz */
} espwn32_proto_mode_t;

/**
 * @brief Installa gli hook di scanning/RX e avvia il task di decodifica.
 *
 * @param idx_scan_start Indice della routine di avvio scan nella tabella ROM.
 * @param idx_rx_handler Indice della routine di gestione RX nella tabella ROM.
 * @return ESP_OK se inizializzato correttamente.
 */
esp_err_t proto_sniffer_init(uint8_t idx_scan_start, uint8_t idx_rx_handler);

/**
 * @brief Ripristina gli handler originali in RAM e arresta lo sniffer.
 */
void proto_sniffer_deinit(uint8_t idx_scan_start, uint8_t idx_rx_handler);

/**
 * @brief Configura il controller per lo scanning ANT+ (2457 MHz, sync 0xAAAAA6C5).
 * @param auto_lock_first_device Se true, passa automaticamente a ANT_SNIFF appena
 *                               rileva un Device Number valido.
 */
esp_err_t proto_configure_ant_scan(bool auto_lock_first_device);

/**
 * @brief Configura il controller per lo sniffing mirato di un sensore ANT+.
 * @param target_device_number Device Number a 16 bit (in host byte order).
 */
esp_err_t proto_configure_ant_sniff(uint16_t target_device_number);

/**
 * @brief Configura il controller per lo sniffing Riitek Rii i8 (2426 MHz).
 */
esp_err_t proto_configure_riitek(void);

/**
 * @brief Prepara un buffer "packet-in-packet" (Sezione V-C.1) incapsulando un
 *        frame proprietario (ANT+ o Riitek) pronto per essere modulato in GFSK.
 *
 * @param out_buf     Buffer di destinazione per il payload wrapper.
 * @param out_max     Capacità massima di out_buf.
 * @param inner_frame Puntatore al frame proprietario completo di preambolo e CRC.
 * @param inner_len   Lunghezza in byte di inner_frame.
 * @return Numero di byte scritti in out_buf, oppure 0 in caso di errore.
 */
size_t proto_wrap_packet_in_packet(uint8_t *out_buf, size_t out_max,
                                   const void *inner_frame, size_t inner_len);

#ifdef __cplusplus
}
#endif

#endif /* ESPWN32_PROTOCOLS_H */