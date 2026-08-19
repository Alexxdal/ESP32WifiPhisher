#ifndef _BLE_IDENTIFY_H
#define _BLE_IDENTIFY_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/*
 * Two independent Bluetooth SIG number spaces are used here:
 *  - "Company Identifier" (16-bit): who made the product, carried in
 *    Manufacturer Specific Data (AD type 0xFF, first 2 bytes).
 *  - "Member UUID" (16-bit): a service the device advertises, carried in
 *    Service UUID / Service Data AD types (0x02 / 0x03 / 0x16).
 * The same vendor can show up in either, and the two tables below are
 * NOT the full official lists (several thousand entries) -- they're the
 * subset verified against Marauder's and GhostESP's production BLE code.
 * Grow them from the official list:
 * https://bitbucket.org/bluetooth-SIG/public/src/main/assigned_numbers/company_identifiers/company_identifiers.yaml
 */

typedef enum {
    BLE_DEV_UNKNOWN = 0,
    BLE_DEV_GENERIC_VENDOR,       /* company/service name known, no specific model */
    BLE_DEV_APPLE_PROXIMITY,      /* AirPods-style "Proximity Pairing" popup */
    BLE_DEV_APPLE_NEARBY_ACTION,  /* "Setup New iPhone"-style popup (also used for spam) */
    BLE_DEV_APPLE_FINDMY,         /* Apple "Nearby Info" broadcast */
    BLE_DEV_AIRTAG,               /* Apple AirTag, lost-mode Find My broadcast */
    BLE_DEV_THIRDPARTY_FINDMY,    /* non-Apple accessory on the Find My network */
    BLE_DEV_TILE,
    BLE_DEV_CHIPOLO,
    BLE_DEV_SAMSUNG_SMARTTAG,     /* see caveat in ble_identify.c: over-broad match */
    BLE_DEV_FLIPPER_ZERO,
    BLE_DEV_FLOCK_CAMERA,         /* see caveat in ble_identify.c: unverified signature */
    BLE_DEV_FAST_PAIR,            /* Google Fast Pair advertisement */
    BLE_DEV_EDDYSTONE,            /* Google Eddystone beacon */
} ble_device_type_t;


typedef struct {
    ble_device_type_t type;
    const char *vendor;    /* e.g. "Apple", NULL if nothing matched */
    const char *label;     /* human string for `type` */
    char        serial[24]; /* only filled in for BLE_DEV_FLOCK_CAMERA today */
} ble_identify_result_t;


/**
 * @brief Classifies one raw advertising payload (the AD structures, not
 * including the BLE header). `name_hint` is used only if the payload
 * itself carries no local name AD structure (0x08/0x09) -- pass a name
 * you remembered from a previous frame from the same device, or NULL.
 */
void ble_identify_classify(const uint8_t *adv, uint8_t adv_len, const char *name_hint, ble_identify_result_t *out);


/**
 * @brief Extracts just the local name (AD type 0x08/0x09) if present.
 * @return true if a name was found and copied into out.
 * 
 */
bool ble_identify_extract_name(const uint8_t *adv, uint8_t adv_len, char *out, size_t out_size);


/** 
 * @brief Looks up a manufacturer company ID. NULL if not in the table. 
 * 
 */
const char *ble_identify_company_name(uint16_t company_id);


/** 
 * @brief Looks up a 16-bit service/member UUID. NULL if not in the table. 
 * 
 */
const char *ble_identify_service_uuid_name(uint16_t uuid16);

#endif