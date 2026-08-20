#ifndef _BLE_SNIFFER_H
#define _BLE_SNIFFER_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"
#include "ble_identify.h"

#define BLE_SNIFFER_MAX_DEVICES     64
#define BLE_SNIFFER_MAX_ADV_LEN     31   /* legacy adv payload cap; longer with
                                             extended adv/scan, see ble_sniffer.c */

typedef enum {
    BLE_SNIFFER_ADDR_PUBLIC = 0,
    BLE_SNIFFER_ADDR_RANDOM = 1,
} ble_sniffer_addr_type_t;


/**
 * @brief A tracked device: sender of advertising/scan-response frames,
 * NOT an active BLE connection between two other devices (see the
 * scope note at the top of ble_sniffer.c).
 */
typedef struct {
    uint8_t  addr[6];               /* human-readable order, not raw little-endian */
    ble_sniffer_addr_type_t addr_type;
    int8_t   last_rssi;
    uint32_t packet_count;
    uint32_t byte_count;
    int64_t  first_seen_us;
    int64_t  last_seen_us;
    uint8_t  last_adv_len;
    uint8_t  last_adv_payload[BLE_SNIFFER_MAX_ADV_LEN];
    char     name[32];              /* persists across frames: the name AD
                                        structure often arrives in a separate
                                        scan-response frame from the same device */
    ble_identify_result_t identify; /* re-classified on every update, see ble_identify.h */
} ble_sniffer_device_t;


/** 
 * @brief Aggregate stats, the BLE equivalent of your WiFi sniffer's counters. 
 * 
 */
typedef struct {
    uint32_t total_packets;
    uint32_t total_bytes;
    uint16_t unique_devices;
} ble_sniffer_stats_t;


/** 
 * @brief Called per frame when the live analyzer is on (dashboard hook). 
 * 
 */
typedef void (*ble_sniffer_frame_cb_t)(const ble_sniffer_device_t *device);


/**
 * @brief Starts passive scanning. Chiama ble_init() (bleMng.h) PRIMA di
 * questa -- lo sniffer non possiede più il ciclo di vita dello stack
 * NimBLE, solo la device table e la scansione GAP.
 */
esp_err_t ble_sniffer_start(void);


/** 
 * @brief Stops passive scanning. Does not tear down the host task. 
 * 
 */
esp_err_t ble_sniffer_stop(void);


/** 
 * @brief True while a scan is active (not the same as the task being alive). 
 * 
 */
bool ble_sniffer_is_running(void);


/** 
 * @brief Enables/disables per-frame streaming via the callback. 
 * 
 */
void ble_sniffer_set_live_analyzer(bool enable);


/** 
 * @brief Registers the live-analyzer callback. 
 * 
 */
void ble_sniffer_set_frame_callback(ble_sniffer_frame_cb_t cb);


/** 
 * @brief Copies up to max_out tracked devices into out. @return count copied. 
 * 
 */
size_t ble_sniffer_get_devices(ble_sniffer_device_t *out, size_t max_out);


/** 
 * @brief Reads current aggregate stats. 
 * 
 */
void ble_sniffer_get_stats(ble_sniffer_stats_t *out);


/** 
 * @brief Clears the device table and stats. Does not affect scan state. 
 * 
 */
void ble_sniffer_clear(void);

#endif