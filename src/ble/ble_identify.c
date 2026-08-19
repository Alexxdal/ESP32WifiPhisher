/*
 * ble_identify.c
 *
 * Generic AD-structure parser + a small, source-verified identification
 * database, ported from real signatures found in Marauder's WiFiScan.cpp
 * and GhostESP's main/scans/ble.c + main/managers/ble_manager.c (both
 * cited inline below). Not a full Bluetooth SIG list -- see the note in
 * ble_identify.h for where to grow it.
 */

#include <string.h>
#include "ble_identify.h"

typedef struct {
    uint16_t    id;
    const char *name;
} id_name_t;


/* Company Identifiers (Manufacturer Specific Data, AD type 0xFF). */
static const id_name_t s_company_ids[] = {
    { 0x004C, "Apple" },
    { 0x0006, "Microsoft" },
    { 0x0075, "Samsung" },
    { 0x00E0, "Google" },
    { 0x00D8, "Tile" },
    { 0x0231, "Chipolo" },
    { 0x004F, "Find My network accessory (non-Apple)" },
};


/*
 * 16-bit Service/Member UUIDs (AD types 0x02/0x03/0x16). The vendor-
 * registered range (0xFE00-0xFEFF roughly) has real-world collisions
 * between vendors -- e.g. GhostESP's own source disagrees with itself
 * on 0xFEE0 (one file says Huawei, another says Xiaomi/Amazfit). Treat
 * entries in that range as "likely", not certain.
 */
static const id_name_t s_service_uuids[] = {
    /* Bluetooth SIG standard services */
    { 0x1800, "Generic Access" },
    { 0x1801, "Generic Attribute" },
    { 0x1802, "Immediate Alert" },
    { 0x1803, "Link Loss" },
    { 0x1804, "Tx Power" },
    { 0x1805, "Current Time" },
    { 0x180A, "Device Information" },
    { 0x180D, "Heart Rate" },
    { 0x180F, "Battery" },
    { 0x1811, "Alert Notification" },
    { 0x1812, "HID" },
    { 0x181A, "Environmental Sensing" },
    /* Vendor-registered, see collision note above */
    { 0xFEAA, "Google Eddystone" },
    { 0xFE9F, "Google Nearby" },
    { 0xFE2C, "Google" },
    { 0xFE95, "Xiaomi" },
    { 0xFEE8, "Xiaomi" },
    { 0xFEE0, "Huawei / Xiaomi Amazfit (contested, see note above)" },
    { 0xFEE7, "Tencent" },
    { 0xFDAC, "Tencent" },
    { 0xFEED, "Tile" },
    { 0xFEEC, "Tile" },
    { 0xFEB8, "Meta/Oculus" },
    { 0xFE07, "Sonos" },
    { 0xFD6F, "Exposure Notification (COVID-19)" },
};


const char *ble_identify_company_name(uint16_t id)
{
    for (size_t i = 0; i < sizeof(s_company_ids) / sizeof(s_company_ids[0]); i++) {
        if (s_company_ids[i].id == id) {
            return s_company_ids[i].name;
        }
    }
    return NULL;
}


const char *ble_identify_service_uuid_name(uint16_t uuid)
{
    for (size_t i = 0; i < sizeof(s_service_uuids) / sizeof(s_service_uuids[0]); i++) {
        if (s_service_uuids[i].id == uuid) {
            return s_service_uuids[i].name;
        }
    }
    return NULL;
}

/* --- generic AD-structure walker --- */

typedef struct {
    bool     has_company;
    uint16_t company_id;
    const uint8_t *mfg_data;   /* payload after the 2-byte company ID */
    uint8_t  mfg_len;

    uint16_t service_uuid16[4];
    uint8_t  service_uuid16_count;

    char     name[32];
    bool     has_name;
} ble_ad_fields_t;


/* Walks the [length][type][data...] TLV chain. Same bounds-check shape
 * as GhostESP's gatt_scan.c tracker-detection loop. */
static void parse_ad_structures(const uint8_t *adv, uint8_t adv_len, ble_ad_fields_t *f)
{
    memset(f, 0, sizeof(*f));

    for (uint16_t i = 0; i < adv_len; ) {
        uint8_t field_len = adv[i];
        if (field_len == 0 || i + field_len >= adv_len) {
            break;   /* malformed or padding -- stop rather than misread */
        }

        uint8_t field_type = adv[i + 1];
        const uint8_t *data = &adv[i + 2];
        uint8_t data_len = field_len - 1;   /* field_len includes the type byte */

        switch (field_type) {

        case 0x02: /* Incomplete List of 16-bit Service UUIDs */
        case 0x03: /* Complete List of 16-bit Service UUIDs */
            for (uint8_t k = 0; k + 1 < data_len && f->service_uuid16_count < 4; k += 2) {
                f->service_uuid16[f->service_uuid16_count++] = data[k] | (data[k + 1] << 8);
            }
            break;

        case 0x16: /* Service Data - 16-bit UUID */
            if (data_len >= 2 && f->service_uuid16_count < 4) {
                f->service_uuid16[f->service_uuid16_count++] = data[0] | (data[1] << 8);
            }
            break;

        case 0x08: /* Shortened Local Name */
        case 0x09: /* Complete Local Name */
            {
                uint8_t n = (data_len < sizeof(f->name) - 1) ? data_len : sizeof(f->name) - 1;
                memcpy(f->name, data, n);
                f->name[n] = '\0';
                f->has_name = true;
            }
            break;

        case 0xFF: /* Manufacturer Specific Data: 2-byte company ID + payload */
            if (data_len >= 2) {
                f->has_company = true;
                f->company_id = data[0] | (data[1] << 8);
                f->mfg_data = data + 2;
                f->mfg_len = data_len - 2;
            }
            break;

        default:
            break;
        }

        i += field_len + 1;
    }
}


bool ble_identify_extract_name(const uint8_t *adv, uint8_t adv_len, char *out, size_t out_size)
{
    ble_ad_fields_t f;
    parse_ad_structures(adv, adv_len, &f);
    if (!f.has_name || out_size == 0) {
        return false;
    }
    size_t n = strlen(f.name);
    if (n >= out_size) {
        n = out_size - 1;
    }
    memcpy(out, f.name, n);
    out[n] = '\0';
    return true;
}


/* Flock Safety camera serial: look for "TN" followed by digits (and a
 * few separators) in the manufacturer payload. Ported from Marauder's
 * isFlockCamera() serial-extraction loop. */
static void extract_flock_serial(const uint8_t *mfg, uint8_t mfg_len, char *out, size_t out_size)
{
    out[0] = '\0';
    if (out_size < 3) {
        return;
    }

    for (uint8_t i = 0; i + 1 < mfg_len; i++) {
        if (mfg[i] != 'T' || mfg[i + 1] != 'N') {
            continue;
        }
        size_t o = 0;
        out[o++] = 'T';
        out[o++] = 'N';
        for (uint8_t k = i + 2; k < mfg_len && o < out_size - 1; k++) {
            char c = (char)mfg[k];
            if (c >= '0' && c <= '9') {
                out[o++] = c;
            } else if (c == ' ' || c == '#' || c == '-') {
                continue;
            } else {
                break;
            }
        }
        out[o] = '\0';
        return;
    }
}


void ble_identify_classify(const uint8_t *adv, uint8_t adv_len,
                            const char *name_hint, ble_identify_result_t *out)
{
    memset(out, 0, sizeof(*out));
    out->type = BLE_DEV_UNKNOWN;

    ble_ad_fields_t f;
    parse_ad_structures(adv, adv_len, &f);

    const char *name = f.has_name ? f.name : name_hint;

    /* Flipper Zero: identified by one of its 3 fixed service UUIDs.
     * Source: GhostESP main/scans/ble/flipper_scan.c */
    for (uint8_t i = 0; i < f.service_uuid16_count; i++) {
        uint16_t u = f.service_uuid16[i];
        if (u == 0x3082 || u == 0x3081 || u == 0x3083) {
            out->type = BLE_DEV_FLIPPER_ZERO;
            out->vendor = "Flipper Devices";
            out->label = "Flipper Zero";
            return;
        }
        if (u == 0xFEED || u == 0xFEEC) {
            out->type = BLE_DEV_TILE;
            out->vendor = "Tile";
            out->label = "Tile tracker";
            return;
        }
        if (u == 0xFE2C) {
            out->type = BLE_DEV_FAST_PAIR;
            out->vendor = "Google";
            out->label = "Fast Pair device";
            return;
        }
        if (u == 0xFEAA) {
            out->type = BLE_DEV_EDDYSTONE;
            out->vendor = "Google";
            out->label = "Eddystone beacon";
            return;
        }
    }

    /* Flock Safety camera: manufacturer 0x09C8 (XUNTONG) + a name
     * pattern. Ported from Marauder's isFlockCamera() -- CAVEAT: this
     * signature isn't independently verified against real hardware by
     * me, only carried over from Marauder's source. Treat matches as
     * "worth investigating", not as confirmed. */
    if (f.has_company && f.company_id == 0x09C8) {
        bool name_matches = (name == NULL);   /* Marauder also flags "no name at all" */
        if (name != NULL) {
            size_t n = strlen(name);
            if ((n == 18 && strncmp(name, "Penguin-", 8) == 0) ||
                strcmp(name, "FS Ext Battery") == 0 ||
                n == 10) {
                name_matches = true;
            }
        }
        if (name_matches) {
            out->type = BLE_DEV_FLOCK_CAMERA;
            out->vendor = "Flock Safety (unverified signature)";
            out->label = "Possible ALPR camera";
            extract_flock_serial(f.mfg_data, f.mfg_len, out->serial, sizeof(out->serial));
            return;
        }
    }

    /* Apple ecosystem, sub-typed by the byte right after the company ID.
     * Source: GhostESP main/scans/ble/gatt_scan.c + main/attacks/ble/ble_spam.c */
    if (f.has_company && f.company_id == 0x004C && f.mfg_len >= 2) {
        uint8_t type_byte = f.mfg_data[0];
        uint8_t type_len  = f.mfg_data[1];

        if (type_byte == 0x12 && type_len == 0x19 && f.mfg_len >= 25) {
            out->type = BLE_DEV_AIRTAG;
            out->vendor = "Apple";
            out->label = "AirTag (Find My / lost mode)";
        } else if (type_byte == 0x07) {
            out->type = BLE_DEV_APPLE_PROXIMITY;
            out->vendor = "Apple";
            out->label = "AirPods-style pairing popup";
        } else if (type_byte == 0x0F) {
            out->type = BLE_DEV_APPLE_NEARBY_ACTION;
            out->vendor = "Apple";
            out->label = "Nearby Action (e.g. \"Setup New iPhone\")";
        } else if (type_byte == 0x10) {
            out->type = BLE_DEV_APPLE_FINDMY;
            out->vendor = "Apple";
            out->label = "Nearby Info";
        } else {
            out->type = BLE_DEV_GENERIC_VENDOR;
            out->vendor = "Apple";
            out->label = "Apple device (unrecognized sub-type)";
        }
        return;
    }

    if (f.has_company && f.company_id == 0x004F) {
        out->type = BLE_DEV_THIRDPARTY_FINDMY;
        out->vendor = "Find My network accessory (non-Apple)";
        out->label = "Third-party Find My tracker";
        return;
    }

    if (f.has_company && f.company_id == 0x00D8) {
        out->type = BLE_DEV_TILE;
        out->vendor = "Tile";
        out->label = "Tile tracker";
        return;
    }

    if (f.has_company && f.company_id == 0x0231) {
        out->type = BLE_DEV_CHIPOLO;
        out->vendor = "Chipolo";
        out->label = "Chipolo tracker";
        return;
    }

    if (f.has_company && f.company_id == 0x0075) {
        /* CAVEAT: 0x0075 is Samsung's generic company ID -- it shows up
         * on phones/earbuds too, not just SmartTags. GhostESP's own
         * gatt_scan.c flags any 0x0075 sighting as a SmartTag; this is
         * ported as-is, so treat it as "probably Samsung", not a
         * confirmed tracker, until you add a better discriminator. */
        out->type = BLE_DEV_SAMSUNG_SMARTTAG;
        out->vendor = "Samsung";
        out->label = "Samsung device (possibly SmartTag)";
        return;
    }

    if (f.has_company) {
        const char *vendor = ble_identify_company_name(f.company_id);
        if (vendor != NULL) {
            out->type = BLE_DEV_GENERIC_VENDOR;
            out->vendor = vendor;
            out->label = vendor;
            return;
        }
    }

    for (uint8_t i = 0; i < f.service_uuid16_count; i++) {
        const char *svc = ble_identify_service_uuid_name(f.service_uuid16[i]);
        if (svc != NULL) {
            out->type = BLE_DEV_GENERIC_VENDOR;
            out->vendor = svc;
            out->label = svc;
            return;
        }
    }
}