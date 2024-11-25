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

#ifndef LIBWIFI_CORE_TAG_H
#define LIBWIFI_CORE_TAG_H

#include <stdint.h>
#include <sys/types.h>

/* 802.11 Tagged Parameter values */
enum libwifi_tag_numbers {
    TAG_SSID = 0,
    TAG_SUPP_RATES = 1,
    // Reserved 2
    TAG_DS_PARAMETER = 3,
    TAG_CF_PARAMETER = 4,
    TAG_TIM = 5,
    TAG_BSS_PARAMETERS = 6,
    TAG_COUNTRY = 7,
    // Reserved 8-9
    TAG_REQUEST = 10,
    TAG_BSS_LOAD = 11,
    TAG_EDCA_PARAMETERS = 12,
    TAG_TSPEC = 13,
    TAG_TCLAS = 14,
    TAG_SCHEDULE = 15,
    TAG_CHALLENGE_TEXT = 16,
    // Reserved 17-31
    TAG_POWER_CONSTRAINT = 32,
    TAG_POWER_CAPABILITY = 33,
    TAG_TPC_REQUEST = 34,
    TAG_TPC_REPORT = 35,
    TAG_SUPPORTED_CHANNELS = 36,
    TAG_CHANNEL_SWITCH_ANNOUNCEMENT = 37,
    TAG_MEASUREMENT_REQUEST = 38,
    TAG_MEASUREMENT_REPORT = 39,
    TAG_QUIET = 40,
    TAG_IBSS_DFS = 41,
    TAG_ERP = 42,
    TAG_TS_DELAY = 43,
    TAG_TCLAS_PROCESSING = 44,
    TAG_HT_CAPABILITIES = 45,
    TAG_QOS_CAPABILITY = 46,
    // Reserved 47
    TAG_RSN = 48,
    // Reserved 49
    TAG_EXTENDED_SUPPORTED_RATES = 50,
    TAG_AP_CHANNEL_REPORT = 51,
    TAG_NEIGHBOR_REPORT = 52,
    TAG_RCPI = 53,
    TAG_MOBILITY_DOMAIN = 54,
    TAG_FAST_BSS_TRANSITION = 55,
    TAG_TIMEOUT_INTERVAL = 56,
    TAG_RIC_DATA = 57,
    TAG_DSE_REGISTERED_LOCATION = 58,
    TAG_SUPPORTED_OPERATING_CLASSES = 59,
    TAG_EXTENDED_CHANNEL_SWITCH_ANNOUNCEMENT = 60,
    TAG_HT_OPERATION = 61,
    TAG_SECONDARY_CHANNEL_OFFSET = 62,
    TAG_BSS_AVERAGE_ACCESS_DELAY = 63,
    TAG_ANTENNA = 64,
    TAG_RSNI = 65,
    TAG_MEASUREMENT_PILOT_TRANSMISSION = 66,
    TAG_BSS_AVAILABLE_ADMISSION_CAPACITY = 67,
    TAG_BSS_AC_ACCESS_DELAY = 68,
    TAG_TIME_ADVERTISEMENT = 69,
    TAG_RM_ENABLED_CAPABILITIES = 70,
    TAG_MULTIPLE_BSSID = 71,
    TAG_BSS_COEXISTENCE = 72,
    TAG_BSS_INTOLERANT_CHANNEL_REPORT = 73,
    TAG_OVERLAPPING_BSS_PARAMETERS = 74,
    TAG_RIC_DESCRIPTOR = 75,
    TAG_MANAGEMENT_MIC = 76,
    // Undefined 77
    TAG_EVENT_REQUEST = 78,
    TAG_EVENT_REPORT = 79,
    TAG_DIAGNOSTIC_REQUEST = 80,
    TAG_DIAGNOSTIC_REPORT = 81,
    TAG_LOCATION_PARAMTERS = 82,
    TAG_NONTRANSMITTED_BSSID_CAPABILITY = 83,
    TAG_SSID_LIST = 84,
    TAG_MULTIPLE_BSSID_INDEX = 85,
    TAG_FMS_DESCRIPTOR = 86,
    TAG_FMS_REQUEST = 87,
    TAG_FMS_RESPONSE = 88,
    TAG_QOS_TRAFFIC_CAPABILITY = 89,
    TAG_BSS_MAX_IDLE_PERIOD = 90,
    TAG_TFS_REQUEST = 91,
    TAG_TFS_RESPONSE = 92,
    TAG_WNM_SLEEP_MODE = 93,
    TAG_TIM_BROADCAST_REQUEST = 94,
    TAG_TIM_BROADCAST_RESPONSE = 95,
    TAG_COLLOCATED_INTERFERENCE_REPORT = 96,
    TAG_CHANNEL_USAGE = 97,
    TAG_TIME_ZONE = 98,
    TAG_DMS_REQUEST = 99,
    TAG_DMS_RESPONSE = 100,
    TAG_LINK_IDENTIFIER = 101,
    TAG_WAKEUP_SCHEDULE = 102,
    // Undefined 103
    TAG_CHANNEL_SWITCH_TIMING = 104,
    TAG_PTI_CONTROL = 105,
    TAG_TPU_BUFFER_STATUS = 106,
    TAG_INTERWORKING = 107,
    TAG_ADVERTISEMENT_PROTOCOL = 108,
    TAG_EXPEDITED_BANDWIDTH_REQUEST = 109,
    TAG_QOS_MAP = 110,
    TAG_ROAMING_CONSORTIUM = 111,
    TAG_EMERGENCY_ALERT_IDENTIFIER = 112,
    TAG_MESH_CONFIGURATION = 113,
    TAG_MESH_ID = 114,
    TAG_MESH_LINK_METRIC_REPORT = 115,
    TAG_CONGESTION_NOTIFICATION = 116,
    TAG_MESH_PEERING_MANAGEMENT = 117,
    TAG_MESH_CHANNEL_SWITCH_PARAMETERS = 118,
    TAG_MESH_AWAKE_WINDOW = 119,
    TAG_BEACON_TIMING = 120,
    TAG_MCCAOP_SETUP_REQUEST = 121,
    TAG_MCCAOP_SETUP_REPLY = 122,
    TAG_MCCAOP_ADVERTISEMENT = 123,
    TAG_MCCAOP_TEARDOWN = 124,
    TAG_GANN = 125,
    TAG_RANN = 126,
    TAG_EXTENDED_CAPABILITIES = 127,
    // Reserved 128-129
    TAG_PREQ = 130,
    TAG_PREP = 131,
    TAG_PERR = 132,
    // Reserved 133-136
    TAG_PXU = 137,
    TAG_PXUC = 138,
    TAG_AUTHENTICATED_MESH_PEERING_EXCHANGE = 139,
    TAG_MIC = 140,
    TAG_DESTINATION_URI = 141,
    TAG_U_APSD_COEXISTENCE = 142,
    TAG_DMG_WAKEUP_SCHEDULE = 143,
    TAG_EXTENDED_SCHEDULE = 144,
    TAG_STA_AVAILABILITY = 145,
    TAG_DMG_TSPEC = 146,
    TAG_NEXT_DMG_ATI = 147,
    // Reserved 149-150
    TAG_DMG_OPERATION = 151,
    TAG_DMG_BSS_PARAMETER_CHANGE = 152,
    TAG_DMG_BEAM_REFINEMENT = 153,
    TAG_CHANNEL_MEASUREMENT_FEEDBACK = 154,
    // Reserved 155-156
    TAG_AWAKE_WINDOW = 157,
    TAG_MULTI_BAND = 158,
    TAG_ADDBA_EXTENSION = 159,
    TAG_NEXTPCP_LIST = 160,
    TAG_PCP_HANDOVER = 161,
    TAG_DMG_LINK_MARGIN = 162,
    TAG_SWITCHING_STREAM = 163,
    TAG_SESSION_TRANSITION = 164,
    TAG_DYNAMIC_TONE_PAIRING_REPORT = 165,
    TAG_CLUSTER_REPORT = 166,
    TAG_RELAY_CAPABILITIES = 167,
    TAG_RELAY_TRANSFER_PARAMETER_SET = 168,
    TAG_BEAMLINK_MAINTENANCE = 169,
    TAG_MULTIPLE_MAC_SUBLAYERS = 170,
    TAG_U_PID = 171,
    TAG_DMG_LINK_ADAPTATION_ACKNOWLEDGEMENT = 172,
    // Reserved 173
    TAG_MCCAOP_ADVERTISEMENT_OVERVIEW = 174,
    TAG_QUIET_PERIOD_REQUEST = 175,
    // Reserved 176
    TAG_QUIET_PERIOD_RESPONSE = 177,
    // Reserved 178-180
    TAG_QMF_POLICY = 181,
    TAG_ECAPC_POLICY = 182,
    TAG_CLUSTER_TIME_OFFSET = 183,
    TAG_INTRA_ACCESS_CATEGORY_PRIORITY = 184,
    TAG_SCS_DESCRIPTOR = 185,
    TAG_QLOAD_REPORT = 186,
    TAG_HCCA_TXOP_UPDATE_COUNT = 187,
    TAG_HIGHER_LAYER_STREAM_ID = 188,
    TAG_GCR_GROUP_ADDRESS = 189,
    TAG_ANTENNA_SECTOR_ID_PATTERN = 190,
    TAG_VHT_CAPABILITIES = 191,
    TAG_VHT_OPERATION = 192,
    TAG_EXTENDED_BSS_LOAD = 193,
    TAG_WIDE_BANDWIDTH_CHANNEL_SWITCH = 194,
    TAG_TRANSMIT_POWER_ENVELOPE = 195,
    TAG_CHANNEL_SWITCH_WRAPPER = 196,
    TAG_AID = 197,
    TAG_QUIET_CHANNEL = 198,
    TAG_UPSIM = 200,
    TAG_REDUCED_NEIGHBOR_REPORT = 201,
    TAG_TVHT_OPERATION = 202,
    // Reserved 203
    TAG_DEVICE_LOCATION = 204,
    TAG_WHITE_SPACE_MAP = 205,
    TAG_FINE_TIMING_MEASUREMENT_PARAMETERS = 206,
    // Reserved 207-220
    TAG_VENDOR_SPECIFIC = 221,
    // Reserved 222-254,
    TAG_ELEMENT_EXTENSION = 255,
};

/**
 * A tagged parameter always consists of a tag number and length
 */
struct libwifi_tag_header {
    uint8_t tag_num;
    uint8_t tag_len;
} __attribute__((packed));

/*
 * A tagged parameter will include a header as well as some body,
 * depending on the tag number. The length of the body buffer is
 * determined with the header.tag_len variable.
 */
struct libwifi_tagged_parameter {
    struct libwifi_tag_header header;
    unsigned char *body;
} __attribute__((packed));

/*
 * A collection of total tagged parameters
 */
struct libwifi_tagged_parameters {
    size_t length;
    unsigned char *parameters;
} __attribute__((packed));

/*
 * Vendor specific tagged parameters have an OUI and Sub-Type
 * to determine their use
 */
struct libwifi_tag_vendor_header {
    unsigned char oui[3];
    int8_t type;
} __attribute__((packed));

/*
 * Element extension tagged parameters have a tag number
 */
struct libwifi_tag_extension_header {
    uint8_t tag_num;
} __attribute__((packed));

/**
 * Add a tagged parameter to a list of frame tagged parameters.
 *
 * @param tagged_parameters A management frame's tagged parameters
 * @param tagged_parameter The new tagged parameter
 */
int libwifi_add_tag(struct libwifi_tagged_parameters *tagged_parameters,
                    struct libwifi_tagged_parameter *tagged_parameter);

/**
 * Remove a tagged parameter from a list of frame tagged parameters.
 *
 * @param tagged_parameters A management frame's tagged parameters
 * @param tag_number Number of the tag to remove
 */
int libwifi_remove_tag(struct libwifi_tagged_parameters *tagged_parameters, int tag_number);

/**
 * Create a tagged parameter from a tag number, length and data.
 * This can be useful when generating tags on their own, for use with
 * action frame body's.
 *
 * @param tagged_parameter A new tagged parameter struct
 * @param tag_number Tagged parameter number
 * @param tag_data The tag body
 * @param tag_length Length of the tag body
 * @return length of the created tag
 */
size_t libwifi_create_tag(struct libwifi_tagged_parameter *tagged_parameter, int tag_number,
                          const unsigned char *tag_data, size_t tag_length);

/**
 * Free a tagged parameters body
 *
 * @param tagged_parameter A used tagged parameter
 */
void libwifi_free_tag(struct libwifi_tagged_parameter *tagged_parameter);

/**
 * Dump a tagged parameter into a raw buffer, for use with other buffers
 * or injection.
 *
 * @param tag A used tagged parameter struct
 * @param buf A buffer for the raw data
 * @param buf_len Length of buf
 */
size_t libwifi_dump_tag(struct libwifi_tagged_parameter *tag, unsigned char *buf, size_t buf_len);

/**
 * Add a tagged parameter via tag number and data to a management frame.
 *
 * @param tagged_parameters A management frame's tagged parameters
 * @param tag_number Tagged parameter to add
 * @param tag_data Data to copy into new tag
 * @param tag_length Length of the new tag
 * @return 0 on success, negative number on error
 */
int libwifi_quick_add_tag(struct libwifi_tagged_parameters *tagged_parameters, int tag_number,
                          const unsigned char *tag_data, size_t tag_length);

/**
 * Check if a tagged parameter is present via tag number.
 *
 * @param tags A tagged parameters list
 * @param tag_number The number of the tagged parameter to find
 * @returns The number of times the supplied tag_number was found in tags
 */
int libwifi_check_tag(struct libwifi_tagged_parameters *tags, int tag_number);

/**
 * Get the name of a tagged parameter via a supplied tag number.
 *
 * @param tag_number The number of the tagged parameter to name
 * @returns The name of the tag
 */
char* libwifi_get_tag_name(int tag_number);

#endif /* LIBWIFI_CORE_TAG_H */
