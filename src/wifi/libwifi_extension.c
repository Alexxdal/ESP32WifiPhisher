#include <esp_log.h>
#include "libwifi_extension.h"


bool libwifi_extract_csa(const struct libwifi_bss *bss, csa_event_t *out)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));

    if (!bss || !bss->tags.parameters || bss->tags.length < 2) return false;

    struct libwifi_tag_iterator it = {0};
    if (libwifi_tag_iterator_init(&it, bss->tags.parameters, bss->tags.length) != 0) {
        return false;
    }

    do {
        const uint8_t id  = it.tag_header->tag_num;
        const uint8_t len = it.tag_header->tag_len;
        const uint8_t *d  = it.tag_data;
        // CSA: id=37, len=3 -> mode, new_channel, count
        if (id == TAG_CHANNEL_SWITCH_ANNOUNCEMENT && len == 3) {
            out->extended    = false;
            out->mode        = d[0];
            out->new_channel = d[1];
            out->count       = d[2];
            out->new_reg_class = 0;
            return true;
        }
        // ECSA: id=60, len>=4 -> mode, new_reg_class, new_channel, count
        if (id == TAG_EXTENDED_CHANNEL_SWITCH_ANNOUNCEMENT && len >= 4) {
            out->extended    = true;
            out->mode        = d[0];
            out->new_reg_class = d[1];
            out->new_channel = d[2];
            out->count       = d[3];
            return true;
        }

    } while (libwifi_tag_iterator_next(&it) != -1);

    return false;
}


uint8_t *find_eapol_frame(uint8_t *buffer, uint16_t len, uint16_t *eapol_len) 
{
    // Cerca pattern LLC/SNAP: AA AA 03 00 00 00 88 8E
    for (int i = 0; i < len - 8; i++) {
        if (buffer[i] == 0xAA && buffer[i+1] == 0xAA && 
            buffer[i+2] == 0x03 && buffer[i+6] == 0x88 && buffer[i+7] == 0x8E) 
        {
            uint8_t *eapol_start = &buffer[i + 8];
            // Header EAPOL: [Vers(1)][Type(1)][Len(2)]
            uint16_t data_len = (eapol_start[2] << 8) | eapol_start[3];
            *eapol_len = 4 + data_len;
            
            if (i + 8 + *eapol_len > len) return NULL; // Safety check
            return eapol_start;
        }
    }
    return NULL;
}


bool libwifi_extract_csa_from_action_frame(const struct libwifi_frame *f, csa_event_t *out)
{
    if (!f || !out) return false;
    memset(out, 0, sizeof(*out));

    if (f->frame_control.type != TYPE_MANAGEMENT ||
        f->frame_control.subtype != SUBTYPE_ACTION) {
        return false;
    }

    if (!f->body || f->len < f->header_len + 2) return false;

    const uint8_t *body = (const uint8_t *)f->body;
    size_t body_len = f->len - f->header_len;

    uint8_t category = body[0];
    uint8_t action   = body[1];

    if (category != ACTION_SPECTRUM_MGMT) return false;
    if (action != SPECTRUM_ACTION_CSA && action != SPECTRUM_ACTION_EXT_CSA) return false;

    // spesso c’è un Dialog Token dopo category+action (1 byte)
    if (body_len < 3) return false;

    // PROVA offset +3 (con dialog token)
    const uint8_t *p = body + 3;
    size_t rem = body_len - 3;
    // parse TLV IE
    while (rem >= 2) {
        uint8_t eid  = p[0];
        uint8_t elen = p[1];
        if (rem < (size_t)(2 + elen)) {
            break;
        }
        const uint8_t *edata = p + 2;

        if (eid == TAG_CHANNEL_SWITCH_ANNOUNCEMENT && elen >= 3) {
            out->extended = false;
            out->mode = edata[0];
            out->new_channel = edata[1];
            out->count = edata[2];
            return true;
        }

        if (eid == TAG_EXTENDED_CHANNEL_SWITCH_ANNOUNCEMENT && elen >= 4) {
            out->extended = true;
            out->mode = edata[0];
            out->new_reg_class = edata[1];
            out->new_channel = edata[2];
            out->count = edata[3];
            return true;
        }

        p   += 2 + elen;
        rem -= 2 + elen;
    }
    // Tentativo 2: offset +2 (senza dialog token)
    p = body + 2;
    rem = body_len - 2;
    while (rem >= 2) {
        uint8_t eid  = p[0];
        uint8_t elen = p[1];
        if (rem < (size_t)(2 + elen)) break;
        const uint8_t *edata = p + 2;

        if (eid == TAG_CHANNEL_SWITCH_ANNOUNCEMENT && elen >= 3) {
            out->extended = false;
            out->mode = edata[0];
            out->new_channel = edata[1];
            out->count = edata[2];
            return true;
        }
        if (eid == TAG_EXTENDED_CHANNEL_SWITCH_ANNOUNCEMENT && elen >= 4) {
            out->extended = true;
            out->mode = edata[0];
            out->new_reg_class = edata[1];
            out->new_channel = edata[2];
            out->count = edata[3];
            return true;
        }

        p   += 2 + elen;
        rem -= 2 + elen;
    }
    return false;
}