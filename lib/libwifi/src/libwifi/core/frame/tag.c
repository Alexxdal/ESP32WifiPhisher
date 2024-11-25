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

#include "tag.h"
#include "tag_iterator.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

int libwifi_add_tag(struct libwifi_tagged_parameters *tags, struct libwifi_tagged_parameter *tag) {
    // Calculate the total length of the new tag
    size_t parameter_len = sizeof(struct libwifi_tag_header) + tag->header.tag_len;

    // Initalise the supplied tagged parameters list, if not already done.
    // Otherwise, extend the allocation to fit the new tag.
    if (tags->length == 0) {
        tags->parameters = malloc(parameter_len);
        if (tags->parameters == NULL) {
            return -ENOMEM;
        }
    } else {
        void *buf = realloc(tags->parameters, tags->length + parameter_len);
        if (buf == NULL) {
            return -ENOMEM;
        }
        tags->parameters = buf;
    }

    // Append the new tag to the list
    memcpy(tags->parameters + tags->length, &tag->header, sizeof(struct libwifi_tag_header));
    memcpy(tags->parameters + tags->length + sizeof(struct libwifi_tag_header), tag->body,
           tag->header.tag_len);

    // Update total tagged parameters length
    tags->length += parameter_len;

    return 0;
}

int libwifi_remove_tag(struct libwifi_tagged_parameters *tags, int tag_number) {
    // Initalise a tag iterator
    struct libwifi_tag_iterator it = {0};
    if (libwifi_tag_iterator_init(&it, tags->parameters, tags->length) != 0) {
        return -EINVAL;
    }

    // Loop through the tagged parameters list until landing on the supplied tag number
    do {
        if (it.tag_header->tag_num == tag_number) {
            // Calculate the length of the tag we're removing, so that we know
            // how many bytes to shrink the tagged parameter list by
            size_t copy_len = tags->length -
                              (it.tag_data - tags->parameters) -
                              (it.tag_header->tag_len + sizeof(struct libwifi_tag_header));
            memcpy(tags->parameters, it.tag_data + it.tag_header->tag_len, copy_len);
            size_t new_len = tags->length - it.tag_header->tag_len - sizeof(struct libwifi_tag_header);
            tags->parameters = realloc(tags->parameters, new_len);
            tags->length = new_len;
            break;
        }
    } while (libwifi_tag_iterator_next(&it) != -1);

    return 0;
}

size_t libwifi_create_tag(struct libwifi_tagged_parameter *tagged_parameter, int tag_number,
                          const unsigned char *tag_data, size_t tag_length) {
    // Initalise the supplied tagged parameter struct
    memset(tagged_parameter, 0, sizeof(struct libwifi_tagged_parameter));
    tagged_parameter->header.tag_len = tag_length;
    tagged_parameter->header.tag_num = tag_number;
    tagged_parameter->body = malloc(tag_length);
    if (tagged_parameter->body == NULL) {
        return -ENOMEM;
    }
    memset(tagged_parameter->body, 0, tag_length);

    // Copy the supplied data into the new tag body
    memcpy(tagged_parameter->body, tag_data, tag_length);

    return sizeof(struct libwifi_tag_header) + tag_length;
}

void libwifi_free_tag(struct libwifi_tagged_parameter *tagged_parameter) {
    free(tagged_parameter->body);
}

size_t libwifi_dump_tag(struct libwifi_tagged_parameter *tag, unsigned char *buf, size_t buf_len) {
    if (tag->header.tag_len > buf_len) {
        return -EINVAL;
    }

    size_t offset = 0;

    memcpy(buf, &tag->header, sizeof(struct libwifi_tag_header));
    offset += sizeof(struct libwifi_tag_header);
    memcpy(buf + offset, tag->body, tag->header.tag_len);
    offset += tag->header.tag_len;

    return sizeof(struct libwifi_tag_header) + tag->header.tag_len;
}

int libwifi_quick_add_tag(struct libwifi_tagged_parameters *tags, int tag_number,
                          const unsigned char *tag_data, size_t tag_length) {
    struct libwifi_tagged_parameter tagged_parameter = {0};

    size_t ret = libwifi_create_tag(&tagged_parameter, tag_number, tag_data, tag_length);
    if (ret <= 0) {
        return ret;
    }

    libwifi_add_tag(tags, &tagged_parameter);
    libwifi_free_tag(&tagged_parameter);

    return 0;
}

int libwifi_check_tag(struct libwifi_tagged_parameters *tags, int tag_number) {
    int tag_count = 0;
    struct libwifi_tag_iterator it = {0};
    if (libwifi_tag_iterator_init(&it, tags->parameters, tags->length) != 0) {
        return -EINVAL;
    }

    do {
        if (it.tag_header->tag_num == tag_number) {
                tag_count++;
        }
    } while (libwifi_tag_iterator_next(&it) != -1);

    return tag_count;
}

char* libwifi_get_tag_name(int tag_number) {
    switch (tag_number) {
        case TAG_SSID:
            return "TAG_SSID";
        case TAG_SUPP_RATES:
            return "TAG_SUPP_RATES";
        case TAG_DS_PARAMETER:
            return "TAG_DS_PARAMETER";
        case TAG_CF_PARAMETER:
            return "TAG_CF_PARAMETER";
        case TAG_TIM:
            return "TAG_TIM";
        case TAG_BSS_PARAMETERS:
            return "TAG_BSS_PARAMETERS";
        case TAG_COUNTRY:
            return "TAG_COUNTRY";
        case TAG_REQUEST:
            return "TAG_REQUEST";
        case TAG_BSS_LOAD:
            return "TAG_BSS_LOAD";
        case TAG_EDCA_PARAMETERS:
            return "TAG_EDCA_PARAMETERS";
        case TAG_TSPEC:
            return "TAG_TSPEC";
        case TAG_TCLAS:
            return "TAG_TCLAS";
        case TAG_SCHEDULE:
            return "TAG_SCHEDULE";
        case TAG_CHALLENGE_TEXT:
            return "TAG_CHALLENGE_TEXT";
        case TAG_POWER_CONSTRAINT:
            return "TAG_POWER_CONSTRAINT";
        case TAG_POWER_CAPABILITY:
            return "TAG_POWER_CAPABILITY";
        case TAG_TPC_REQUEST:
            return "TAG_TPC_REQUEST";
        case TAG_TPC_REPORT:
            return "TAG_TPC_REPORT";
        case TAG_SUPPORTED_CHANNELS:
            return "TAG_SUPPORTED_CHANNELS";
        case TAG_CHANNEL_SWITCH_ANNOUNCEMENT:
            return "TAG_CHANNEL_SWITCH_ANNOUNCEMENT";
        case TAG_MEASUREMENT_REQUEST:
            return "TAG_MEASUREMENT_REQUEST";
        case TAG_MEASUREMENT_REPORT:
            return "TAG_MEASUREMENT_REPORT";
        case TAG_QUIET:
            return "TAG_QUIET";
        case TAG_IBSS_DFS:
            return "TAG_IBSS_DFS";
        case TAG_ERP:
            return "TAG_ERP";
        case TAG_TS_DELAY:
            return "TAG_TS_DELAY";
        case TAG_TCLAS_PROCESSING:
            return "TAG_TCLAS_PROCESSING";
        case TAG_HT_CAPABILITIES:
            return "TAG_HT_CAPABILITIES";
        case TAG_QOS_CAPABILITY:
            return "TAG_QOS_CAPABILITY";
        case TAG_RSN:
            return "TAG_RSN";
        case TAG_EXTENDED_SUPPORTED_RATES:
            return "TAG_EXTENDED_SUPPORTED_RATES";
        case TAG_AP_CHANNEL_REPORT:
            return "TAG_AP_CHANNEL_REPORT";
        case TAG_NEIGHBOR_REPORT:
            return "TAG_NEIGHBOR_REPORT";
        case TAG_RCPI:
            return "TAG_RCPI";
        case TAG_MOBILITY_DOMAIN:
            return "TAG_MOBILITY_DOMAIN";
        case TAG_FAST_BSS_TRANSITION:
            return "TAG_FAST_BSS_TRANSITION";
        case TAG_TIMEOUT_INTERVAL:
            return "TAG_TIMEOUT_INTERVAL";
        case TAG_RIC_DATA:
            return "TAG_RIC_DATA";
        case TAG_DSE_REGISTERED_LOCATION:
            return "TAG_DSE_REGISTERED_LOCATION";
        case TAG_SUPPORTED_OPERATING_CLASSES:
            return "TAG_SUPPORTED_OPERATING_CLASSES";
        case TAG_EXTENDED_CHANNEL_SWITCH_ANNOUNCEMENT:
            return "TAG_EXTENDED_CHANNEL_SWITCH_ANNOUNCEMENT";
        case TAG_HT_OPERATION:
            return "TAG_HT_OPERATION";
        case TAG_SECONDARY_CHANNEL_OFFSET:
            return "TAG_SECONDARY_CHANNEL_OFFSET";
        case TAG_BSS_AVERAGE_ACCESS_DELAY:
            return "TAG_BSS_AVERAGE_ACCESS_DELAY";
        case TAG_ANTENNA:
            return "TAG_ANTENNA";
        case TAG_RSNI:
            return "TAG_RSNI";
        case TAG_MEASUREMENT_PILOT_TRANSMISSION:
            return "TAG_MEASUREMENT_PILOT_TRANSMISSION";
        case TAG_BSS_AVAILABLE_ADMISSION_CAPACITY:
            return "TAG_BSS_AVAILABLE_ADMISSION_CAPACITY";
        case TAG_BSS_AC_ACCESS_DELAY:
            return "TAG_BSS_AC_ACCESS_DELAY";
        case TAG_TIME_ADVERTISEMENT:
            return "TAG_TIME_ADVERTISEMENT";
        case TAG_RM_ENABLED_CAPABILITIES:
            return "TAG_RM_ENABLED_CAPABILITIES";
        case TAG_MULTIPLE_BSSID:
            return "TAG_MULTIPLE_BSSID";
        case TAG_BSS_COEXISTENCE:
            return "TAG_BSS_COEXISTENCE";
        case TAG_BSS_INTOLERANT_CHANNEL_REPORT:
            return "TAG_BSS_INTOLERANT_CHANNEL_REPORT";
        case TAG_OVERLAPPING_BSS_PARAMETERS:
            return "TAG_OVERLAPPING_BSS_PARAMETERS";
        case TAG_RIC_DESCRIPTOR:
            return "TAG_RIC_DESCRIPTOR";
        case TAG_MANAGEMENT_MIC:
            return "TAG_MANAGEMENT_MIC";
        case TAG_EVENT_REQUEST:
            return "TAG_EVENT_REQUEST";
        case TAG_EVENT_REPORT:
            return "TAG_EVENT_REPORT";
        case TAG_DIAGNOSTIC_REQUEST:
            return "TAG_DIAGNOSTIC_REQUEST";
        case TAG_DIAGNOSTIC_REPORT:
            return "TAG_DIAGNOSTIC_REPORT";
        case TAG_LOCATION_PARAMTERS:
            return "TAG_LOCATION_PARAMTERS";
        case TAG_NONTRANSMITTED_BSSID_CAPABILITY:
            return "TAG_NONTRANSMITTED_BSSID_CAPABILITY";
        case TAG_SSID_LIST:
            return "TAG_SSID_LIST";
        case TAG_MULTIPLE_BSSID_INDEX:
            return "TAG_MULTIPLE_BSSID_INDEX";
        case TAG_FMS_DESCRIPTOR:
            return "TAG_FMS_DESCRIPTOR";
        case TAG_FMS_REQUEST:
            return "TAG_FMS_REQUEST";
        case TAG_FMS_RESPONSE:
            return "TAG_FMS_RESPONSE";
        case TAG_QOS_TRAFFIC_CAPABILITY:
            return "TAG_QOS_TRAFFIC_CAPABILITY";
        case TAG_BSS_MAX_IDLE_PERIOD:
            return "TAG_BSS_MAX_IDLE_PERIOD";
        case TAG_TFS_REQUEST:
            return "TAG_TFS_REQUEST";
        case TAG_TFS_RESPONSE:
            return "TAG_TFS_RESPONSE";
        case TAG_WNM_SLEEP_MODE:
            return "TAG_WNM_SLEEP_MODE";
        case TAG_TIM_BROADCAST_REQUEST:
            return "TAG_TIM_BROADCAST_REQUEST";
        case TAG_TIM_BROADCAST_RESPONSE:
            return "TAG_TIM_BROADCAST_RESPONSE";
        case TAG_COLLOCATED_INTERFERENCE_REPORT:
            return "TAG_COLLOCATED_INTERFERENCE_REPORT";
        case TAG_CHANNEL_USAGE:
            return "TAG_CHANNEL_USAGE";
        case TAG_TIME_ZONE:
            return "TAG_TIME_ZONE";
        case TAG_DMS_REQUEST:
            return "TAG_DMS_REQUEST";
        case TAG_DMS_RESPONSE:
            return "TAG_DMS_RESPONSE";
        case TAG_LINK_IDENTIFIER:
            return "TAG_LINK_IDENTIFIER";
        case TAG_WAKEUP_SCHEDULE:
            return "TAG_WAKEUP_SCHEDULE";
        case TAG_CHANNEL_SWITCH_TIMING:
            return "TAG_CHANNEL_SWITCH_TIMING";
        case TAG_PTI_CONTROL:
            return "TAG_PTI_CONTROL";
        case TAG_TPU_BUFFER_STATUS:
            return "TAG_TPU_BUFFER_STATUS";
        case TAG_INTERWORKING:
            return "TAG_INTERWORKING";
        case TAG_ADVERTISEMENT_PROTOCOL:
            return "TAG_ADVERTISEMENT_PROTOCOL";
        case TAG_EXPEDITED_BANDWIDTH_REQUEST:
            return "TAG_EXPEDITED_BANDWIDTH_REQUEST";
        case TAG_QOS_MAP:
            return "TAG_QOS_MAP";
        case TAG_ROAMING_CONSORTIUM:
            return "TAG_ROAMING_CONSORTIUM";
        case TAG_EMERGENCY_ALERT_IDENTIFIER:
            return "TAG_EMERGENCY_ALERT_IDENTIFIER";
        case TAG_MESH_CONFIGURATION:
            return "TAG_MESH_CONFIGURATION";
        case TAG_MESH_ID:
            return "TAG_MESH_ID";
        case TAG_MESH_LINK_METRIC_REPORT:
            return "TAG_MESH_LINK_METRIC_REPORT";
        case TAG_CONGESTION_NOTIFICATION:
            return "TAG_CONGESTION_NOTIFICATION";
        case TAG_MESH_PEERING_MANAGEMENT:
            return "TAG_MESH_PEERING_MANAGEMENT";
        case TAG_MESH_CHANNEL_SWITCH_PARAMETERS:
            return "TAG_MESH_CHANNEL_SWITCH_PARAMETERS";
        case TAG_MESH_AWAKE_WINDOW:
            return "TAG_MESH_AWAKE_WINDOW";
        case TAG_BEACON_TIMING:
            return "TAG_BEACON_TIMING";
        case TAG_MCCAOP_SETUP_REQUEST:
            return "TAG_MCCAOP_SETUP_REQUEST";
        case TAG_MCCAOP_SETUP_REPLY:
            return "TAG_MCCAOP_SETUP_REPLY";
        case TAG_MCCAOP_ADVERTISEMENT:
            return "TAG_MCCAOP_ADVERTISEMENT";
        case TAG_MCCAOP_TEARDOWN:
            return "TAG_MCCAOP_TEARDOWN";
        case TAG_GANN:
            return "TAG_GANN";
        case TAG_RANN:
            return "TAG_RANN";
        case TAG_EXTENDED_CAPABILITIES:
            return "TAG_EXTENDED_CAPABILITIES";
        case TAG_PREQ:
            return "TAG_PREQ";
        case TAG_PREP:
            return "TAG_PREP";
        case TAG_PERR:
            return "TAG_PERR";
        case TAG_PXU:
            return "TAG_PXU";
        case TAG_PXUC:
            return "TAG_PXUC";
        case TAG_AUTHENTICATED_MESH_PEERING_EXCHANGE:
            return "TAG_AUTHENTICATED_MESH_PEERING_EXCHANGE";
        case TAG_MIC:
            return "TAG_MIC";
        case TAG_DESTINATION_URI:
            return "TAG_DESTINATION_URI";
        case TAG_U_APSD_COEXISTENCE:
            return "TAG_U_APSD_COEXISTENCE";
        case TAG_DMG_WAKEUP_SCHEDULE:
            return "TAG_DMG_WAKEUP_SCHEDULE";
        case TAG_EXTENDED_SCHEDULE:
            return "TAG_EXTENDED_SCHEDULE";
        case TAG_STA_AVAILABILITY:
            return "TAG_STA_AVAILABILITY";
        case TAG_DMG_TSPEC:
            return "TAG_DMG_TSPEC";
        case TAG_NEXT_DMG_ATI:
            return "TAG_NEXT_DMG_ATI";
        case TAG_DMG_OPERATION:
            return "TAG_DMG_OPERATION";
        case TAG_DMG_BSS_PARAMETER_CHANGE:
            return "TAG_DMG_BSS_PARAMETER_CHANGE";
        case TAG_DMG_BEAM_REFINEMENT:
            return "TAG_DMG_BEAM_REFINEMENT";
        case TAG_CHANNEL_MEASUREMENT_FEEDBACK:
            return "TAG_CHANNEL_MEASUREMENT_FEEDBACK";
        case TAG_AWAKE_WINDOW:
            return "TAG_AWAKE_WINDOW";
        case TAG_MULTI_BAND:
            return "TAG_MULTI_BAND";
        case TAG_ADDBA_EXTENSION:
            return "TAG_ADDBA_EXTENSION";
        case TAG_NEXTPCP_LIST:
            return "TAG_NEXTPCP_LIST";
        case TAG_PCP_HANDOVER:
            return "TAG_PCP_HANDOVER";
        case TAG_DMG_LINK_MARGIN:
            return "TAG_DMG_LINK_MARGIN";
        case TAG_SWITCHING_STREAM:
            return "TAG_SWITCHING_STREAM";
        case TAG_SESSION_TRANSITION:
            return "TAG_SESSION_TRANSITION";
        case TAG_DYNAMIC_TONE_PAIRING_REPORT:
            return "TAG_DYNAMIC_TONE_PAIRING_REPORT";
        case TAG_CLUSTER_REPORT:
            return "TAG_CLUSTER_REPORT";
        case TAG_RELAY_CAPABILITIES:
            return "TAG_RELAY_CAPABILITIES";
        case TAG_RELAY_TRANSFER_PARAMETER_SET:
            return "TAG_RELAY_TRANSFER_PARAMETER_SET";
        case TAG_BEAMLINK_MAINTENANCE:
            return "TAG_BEAMLINK_MAINTENANCE";
        case TAG_MULTIPLE_MAC_SUBLAYERS:
            return "TAG_MULTIPLE_MAC_SUBLAYERS";
        case TAG_U_PID:
            return "TAG_U_PID";
        case TAG_DMG_LINK_ADAPTATION_ACKNOWLEDGEMENT:
            return "TAG_DMG_LINK_ADAPTATION_ACKNOWLEDGEMENT";
        case TAG_MCCAOP_ADVERTISEMENT_OVERVIEW:
            return "TAG_MCCAOP_ADVERTISEMENT_OVERVIEW";
        case TAG_QUIET_PERIOD_REQUEST:
            return "TAG_QUIET_PERIOD_REQUEST";
        case TAG_QUIET_PERIOD_RESPONSE:
            return "TAG_QUIET_PERIOD_RESPONSE";
        case TAG_QMF_POLICY:
            return "TAG_QMF_POLICY";
        case TAG_ECAPC_POLICY:
            return "TAG_ECAPC_POLICY";
        case TAG_CLUSTER_TIME_OFFSET:
            return "TAG_CLUSTER_TIME_OFFSET";
        case TAG_INTRA_ACCESS_CATEGORY_PRIORITY:
            return "TAG_INTRA_ACCESS_CATEGORY_PRIORITY";
        case TAG_SCS_DESCRIPTOR:
            return "TAG_SCS_DESCRIPTOR";
        case TAG_QLOAD_REPORT:
            return "TAG_QLOAD_REPORT";
        case TAG_HCCA_TXOP_UPDATE_COUNT:
            return "TAG_HCCA_TXOP_UPDATE_COUNT";
        case TAG_HIGHER_LAYER_STREAM_ID:
            return "TAG_HIGHER_LAYER_STREAM_ID";
        case TAG_GCR_GROUP_ADDRESS:
            return "TAG_GCR_GROUP_ADDRESS";
        case TAG_ANTENNA_SECTOR_ID_PATTERN:
            return "TAG_ANTENNA_SECTOR_ID_PATTERN";
        case TAG_VHT_CAPABILITIES:
            return "TAG_VHT_CAPABILITIES";
        case TAG_VHT_OPERATION:
            return "TAG_VHT_OPERATION";
        case TAG_EXTENDED_BSS_LOAD:
            return "TAG_EXTENDED_BSS_LOAD";
        case TAG_WIDE_BANDWIDTH_CHANNEL_SWITCH:
            return "TAG_WIDE_BANDWIDTH_CHANNEL_SWITCH";
        case TAG_TRANSMIT_POWER_ENVELOPE:
            return "TAG_TRANSMIT_POWER_ENVELOPE";
        case TAG_CHANNEL_SWITCH_WRAPPER:
            return "TAG_CHANNEL_SWITCH_WRAPPER";
        case TAG_AID:
            return "TAG_AID";
        case TAG_QUIET_CHANNEL:
            return "TAG_QUIET_CHANNEL";
        case TAG_UPSIM:
            return "TAG_UPSIM";
        case TAG_REDUCED_NEIGHBOR_REPORT:
            return "TAG_REDUCED_NEIGHBOR_REPORT";
        case TAG_TVHT_OPERATION:
            return "TAG_TVHT_OPERATION";
        case TAG_DEVICE_LOCATION:
            return "TAG_DEVICE_LOCATION";
        case TAG_WHITE_SPACE_MAP:
            return "TAG_WHITE_SPACE_MAP";
        case TAG_FINE_TIMING_MEASUREMENT_PARAMETERS:
            return "TAG_FINE_TIMING_MEASUREMENT_PARAMETERS";
        case TAG_VENDOR_SPECIFIC:
            return "TAG_VENDOR_SPECIFIC";
        case TAG_ELEMENT_EXTENSION:
            return "TAG_ELEMENT_EXTENSION";
        default:
            return "Unknown Tag";
    }
}
