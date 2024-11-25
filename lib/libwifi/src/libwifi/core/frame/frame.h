/* Copyright 2021 The libwifi Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef LIBWIFI_CORE_FRAME_H
#define LIBWIFI_CORE_FRAME_H

#include "../../core/misc/byteswap.h"
#include "../../core/misc/radiotap.h"

#include <stdint.h>
#include <sys/types.h>

/* libwifi_frame Flags */
#define LIBWIFI_FLAGS_FCS_PRESENT (1 << 0)
#define LIBWIFI_FLAGS_IS_QOS (1 << 1)
#define LIBWIFI_FLAGS_IS_ORDERED (1 << 2)
#define LIBWIFI_FLAGS_RADIOTAP_PRESENT (1 << 3)

/* Defined frame types and sub-types */
enum libwifi_frame_type {
    TYPE_MANAGEMENT = 0,
    TYPE_CONTROL = 1,
    TYPE_DATA = 2,
    TYPE_EXTENSION = 3,
};
enum libwifi_mgmt_subtypes {
    SUBTYPE_ASSOC_REQ = 0,
    SUBTYPE_ASSOC_RESP = 1,
    SUBTYPE_REASSOC_REQ = 2,
    SUBTYPE_REASSOC_RESP = 3,
    SUBTYPE_PROBE_REQ = 4,
    SUBTYPE_PROBE_RESP = 5,
    SUBTYPE_TIME_ADV = 6,
    // Reserved = 7,
    SUBTYPE_BEACON = 8,
    SUBTYPE_ATIM = 9,
    SUBTYPE_DISASSOC = 10,
    SUBTYPE_AUTH = 11,
    SUBTYPE_DEAUTH = 12,
    SUBTYPE_ACTION = 13,
    SUBTYPE_ACTION_NOACK = 14,
    // Reserved = 15,
};
enum libwifi_control_subtypes {
    // Reserved = 0-3,
    SUBTYPE_TACK = 3,
    SUBTYPE_BEAMFORM_REPORT_POLL = 4,
    SUBTYPE_VHT_NDP_ANNOUNCE = 5,
    SUBTYPE_CF_EXTENSION = 6,
    SUBTYPE_WRAPPER = 7,
    SUBTYPE_BLOCK_ACK_REQ = 8,
    SUBTYPE_BLOCK_ACK = 9,
    SUBTYPE_PS_POLL = 10,
    SUBTYPE_RTS = 11,
    SUBTYPE_CTS = 12,
    SUBTYPE_ACK = 13,
    SUBTYPE_CF_END = 14,
    SUBTYPE_CF_END_CF_ACK = 15,
};
enum libwifi_control_extension_subtypes {
    // Reserved = 0-1,
    SUBTYPE_CF_EXT_POLL = 2,
    SUBTYPE_CF_EXT_SPR = 3,
    SUBTYPE_CF_EXT_GRANT = 4,
    SUBTYPE_CF_EXT_DMG_CTS = 5,
    SUBTYPE_CF_EXT_DMG_DTS = 6,
    SUBTYPE_CF_EXT_GRANT_ACK = 7,
    SUBTYPE_CF_EXT_SSW = 8,
    SUBTYPE_CF_EXT_SSW_FEEDBACK = 9,
    SUBTYPE_CF_EXT_SSW_ACK = 10,
    // Reserved = 11-15,
};
enum libwifi_data_subtypes {
    SUBTYPE_DATA = 0,
    // Reserved = 1-3,
    SUBTYPE_DATA_NULL = 4,
    // Reserved = 4-7,
    SUBTYPE_DATA_QOS_DATA = 8,
    SUBTYPE_DATA_QOS_DATA_CF_ACK = 9,
    SUBTYPE_DATA_QOS_DATA_CF_POLL = 10,
    SUBTYPE_DATA_QOS_DATA_CF_ACK_CF_POLL = 11,
    SUBTYPE_DATA_QOS_NULL = 12,
    // Reserved = 13,
    SUBTYPE_DATA_QOS_CF_POLL = 14,
    SUBTYPE_DATA_QOS_CF_ACK_CF_POLL = 15,
};
enum libwifi_extension_subtypes {
    SUBTYPE_EXTENSION_DMG_BEACON = 0,
    SUBTYPE_EXTENSION_SIG_BEACON = 1,
    // Reserved = 2-15
};

/*
 * libwifi Representation of an 802.11 Frame Control Field's Flags.
 */

struct libwifi_frame_ctrl_flags {
    unsigned int to_ds : 1;
    unsigned int from_ds : 1;
    unsigned int more_frags : 1;
    unsigned int retry : 1;
    unsigned int power_mgmt : 1;
    unsigned int more_data : 1;
    unsigned int protect : 1;
    unsigned int ordered : 1;
} __attribute__((packed));

/*
 * libwifi Representation of an 802.11 Frame Control Field.
 */
struct libwifi_frame_ctrl {
    unsigned int version : 2;
    unsigned int type : 2;
    unsigned int subtype : 4;
    struct libwifi_frame_ctrl_flags flags;
} __attribute__((packed));

/*
 * libwifi Representation of an 802.11 Sequence Control Field.
 */
struct libwifi_seq_control {
    unsigned int fragment_number : 4;
    unsigned int sequence_number : 12;
} __attribute__((packed));

/*
 * libwifi Representation of an 802.11 Data QoS Control Field.
 *
 * As the bits of the QoS Control Field can vary depending on other
 * factors, generic bit names are used here.
 */
struct libwifi_qos_control {
    unsigned int bit1 : 1;
    unsigned int bit2 : 1;
    unsigned int bit3 : 1;
    unsigned int bit4 : 1;
    unsigned int bit5 : 1;
    unsigned int bit6 : 1;
    unsigned int bit7 : 1;
    unsigned int bit8 : 1;
    unsigned int bit9 : 1;
    unsigned int bit10 : 1;
    unsigned int bit11 : 1;
    unsigned int bit12 : 1;
    unsigned int bit13 : 1;
    unsigned int bit14 : 1;
    unsigned int bit15 : 1;
    unsigned int bit16 : 1;
} __attribute__((packed));

/*
 * libwifi Representation of an ordered Management Frame header.
 *
 * ┌───────────────────────────┐
 * │    Frame Control Field    │  ── 2 Bytes
 * ├───────────────────────────┤
 * │          Duration         │  ── 2 Bytes
 * ├───────────────────────────┤
 * │          Address 1        │  ── 6 Bytes
 * ├───────────────────────────┤
 * │          Address 2        │  ── 6 Bytes
 * ├───────────────────────────┤
 * │          Address 3        │  ── 6 Bytes
 * ├───────────────────────────┤
 * │      Sequence Control     │  ── 2 Bytes
 * ├───────────────────────────┤
 * │         HT Control        │  ── 4 Bytes
 * └───────────────────────────┘
 */
struct libwifi_mgmt_ordered_frame_header {
    struct libwifi_frame_ctrl frame_control;
    uint16_t duration;
    unsigned char addr1[6];
    unsigned char addr2[6];
    unsigned char addr3[6];
    struct libwifi_seq_control seq_control;
    uint32_t ht_control;
} __attribute__((packed));

/*
 * libwifi Representation of an unordered Management Frame header.
 *
 * ┌───────────────────────────┐
 * │    Frame Control Field    │  ── 2 Bytes
 * ├───────────────────────────┤
 * │          Duration         │  ── 2 Bytes
 * ├───────────────────────────┤
 * │          Address 1        │  ── 6 Bytes
 * ├───────────────────────────┤
 * │          Address 2        │  ── 6 Bytes
 * ├───────────────────────────┤
 * │          Address 3        │  ── 6 Bytes
 * ├───────────────────────────┤
 * │      Sequence Control     │  ── 2 Bytes
 * └───────────────────────────┘
 */
struct libwifi_mgmt_unordered_frame_header {
    struct libwifi_frame_ctrl frame_control;
    uint16_t duration;
    unsigned char addr1[6];
    unsigned char addr2[6];
    unsigned char addr3[6];
    struct libwifi_seq_control seq_control;
} __attribute__((packed));

/*
 * libwifi Representation of a Control Frame header.
 *
 * ┌───────────────────────────┐
 * │    Frame Control Field    │  ── 2 Bytes
 * ├───────────────────────────┤
 * │          Duration         │  ── 2 Bytes
 * └───────────────────────────┘
 */
struct libwifi_ctrl_frame_header {
    struct libwifi_frame_ctrl frame_control;
    uint16_t duration;
} __attribute__((packed));

/*
 * libwifi Representation of a non-QoS Data Frame header.
 *
 * ┌───────────────────────────┐
 * │    Frame Control Field    │  ── 2 Bytes
 * ├───────────────────────────┤
 * │          Duration         │  ── 2 Bytes
 * ├───────────────────────────┤
 * │          Address 1        │  ── 6 Bytes
 * ├───────────────────────────┤
 * │          Address 2        │  ── 6 Bytes
 * ├───────────────────────────┤
 * │          Address 3        │  ── 6 Bytes
 * ├───────────────────────────┤
 * │      Sequence Control     │  ── 2 Bytes
 * └───────────────────────────┘
 */
struct libwifi_data_frame_header {
    struct libwifi_frame_ctrl frame_control;
    uint16_t duration;
    unsigned char addr1[6];
    unsigned char addr2[6];
    unsigned char addr3[6];
    struct libwifi_seq_control seq_control;
} __attribute__((packed));

/*
 * libwifi Representation of a QoS Data Frame header.
 *
 * ┌───────────────────────────┐
 * │    Frame Control Field    │  ── 2 Bytes
 * ├───────────────────────────┤
 * │          Duration         │  ── 2 Bytes
 * ├───────────────────────────┤
 * │          Address 1        │  ── 6 Bytes
 * ├───────────────────────────┤
 * │          Address 2        │  ── 6 Bytes
 * ├───────────────────────────┤
 * │          Address 3        │  ── 6 Bytes
 * ├───────────────────────────┤
 * │      Sequence Control     │  ── 2 Bytes
 * ├───────────────────────────┤
 * │         QoS Control       │  ── 2 Bytes
 * └───────────────────────────┘
 */
struct libwifi_data_qos_frame_header {
    struct libwifi_frame_ctrl frame_control;
    uint16_t duration;
    unsigned char addr1[6];
    unsigned char addr2[6];
    unsigned char addr3[6];
    struct libwifi_seq_control seq_control;
    struct libwifi_qos_control qos_control;
} __attribute__((packed));

/*
 * Union of all frame type headers for use with a libwifi_frame struct
 */
union libwifi_frame_header {
    struct libwifi_mgmt_ordered_frame_header mgmt_ordered;
    struct libwifi_mgmt_unordered_frame_header mgmt_unordered;
    struct libwifi_ctrl_frame_header ctrl;
    struct libwifi_data_frame_header data;
    struct libwifi_data_qos_frame_header data_qos;
};

/*
 * Union of all Management Frame headers
 */
union libwifi_mgmt_frame_header {
    struct libwifi_mgmt_ordered_frame_header ordered;
    struct libwifi_mgmt_unordered_frame_header unordered;
};

/*
 * A libwifi_frame struct is used to represent any type of 802.11
 * frame in libwifi.
 */
struct libwifi_frame {
    struct libwifi_radiotap_info *radiotap_info;
    uint16_t flags;
    struct libwifi_frame_ctrl frame_control;
    size_t len;
    union libwifi_frame_header header;
    size_t header_len;
    unsigned char *body;
};

/**
 * Convert a sniffed 802.11 frame into a libwifi_frame.
 *
 * @param fi A libwifi_frame struct
 * @param frame An 802.11 frame
 * @param frame_len Length of the sniffed 802.11 frame
 * @return
 */
int libwifi_get_wifi_frame(struct libwifi_frame *fi, const unsigned char *frame, size_t frame_len,
                           int radiotap);

/**
 * Free any dynamically allocated data inside a libwifi_frame.
 *
 * @param fi A libwifi_frame struct
 */
void libwifi_free_wifi_frame(struct libwifi_frame *fi);

#endif /* LIBWIFI_CORE_FRAME_H */
