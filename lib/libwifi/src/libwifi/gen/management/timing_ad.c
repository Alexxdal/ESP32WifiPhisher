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

#include "common.h"
#include "timing_ad.h"
#include "../../core/frame/management/timing_ad.h"
#include "../../core/misc/epoch.h"
#include "../../core/frame/tag.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

int libwifi_create_timing_advert(struct libwifi_timing_advert *adv,
                                 const unsigned char destination[6],
                                 const unsigned char transmitter[6],
                                 const unsigned char address3[6],
                                 struct libwifi_timing_advert_fields *adv_fields,
                                 const char country[3],
                                 uint16_t max_reg_power,
                                 uint8_t max_tx_power,
                                 uint8_t tx_power_used,
                                 uint8_t noise_floor) {
    memset(adv, 0, sizeof(struct libwifi_timing_advert));

    adv->frame_header.frame_control.type = TYPE_MANAGEMENT;
    adv->frame_header.frame_control.subtype = SUBTYPE_TIME_ADV;
    memcpy(&adv->frame_header.addr1, destination, 6);
    memcpy(&adv->frame_header.addr2, transmitter, 6);
    memcpy(&adv->frame_header.addr3, address3, 6);

    adv->fixed_parameters.timestamp = BYTESWAP64(libwifi_get_epoch());
    adv->fixed_parameters.measurement_pilot_interval = LIBWIFI_DEFAULT_BEACON_INTERVAL;
    adv->fixed_parameters.beacon_interval = LIBWIFI_DEFAULT_BEACON_INTERVAL;
    adv->fixed_parameters.capabilities_information = BYTESWAP16(LIBWIFI_DEFAULT_AP_CAPABS);
    memcpy(adv->fixed_parameters.country, country, sizeof(adv->fixed_parameters.country));
    adv->fixed_parameters.max_reg_power = BYTESWAP16(max_reg_power);
    adv->fixed_parameters.max_tx_power = max_tx_power;
    adv->fixed_parameters.tx_power_used = tx_power_used;
    adv->fixed_parameters.noise_floor = noise_floor;

    if (adv_fields == NULL) {
        return -EINVAL;
    }

    // Maximum element size is 17
    unsigned char element_data[17] = {0};
    size_t element_data_len = 0;
    int offset = 0;

    memcpy(element_data, &adv_fields->timing_capabilities, sizeof(adv_fields->timing_capabilities));
    offset += sizeof(adv_fields->timing_capabilities);

    switch (adv_fields->timing_capabilities) {
        case 1: { /* Time Value and Time Error fields present */
            memcpy(element_data + offset, &adv_fields->time_value, sizeof(adv_fields->time_value));
            offset += sizeof(adv_fields->time_value);
            memcpy(element_data + offset, &adv_fields->time_error, sizeof(adv_fields->time_error));
            offset += sizeof(adv_fields->time_error);
            break;
        }
        case 2: { /* Time Value, Time Error, and Time Update fields present */
            memcpy(element_data + offset, &adv_fields->time_value, sizeof(adv_fields->time_value));
            offset += sizeof(adv_fields->time_value);
            memcpy(element_data + offset, &adv_fields->time_error, sizeof(adv_fields->time_error));
            offset += sizeof(adv_fields->time_error);
            memcpy(element_data + offset, &adv_fields->time_update, sizeof(adv_fields->time_update));
            offset += sizeof(adv_fields->time_update);
            break;
        }
        default:
            break;
    }

    element_data_len = offset;

    int ret = libwifi_quick_add_tag(&adv->tags, TAG_TIME_ADVERTISEMENT, element_data, element_data_len);

    return ret;
}

size_t libwifi_get_timing_advert_length(struct libwifi_timing_advert *adv) {
    return sizeof(struct libwifi_mgmt_unordered_frame_header) +
           sizeof(struct libwifi_timing_advert_fixed_params) +
           adv->tags.length;
}

size_t libwifi_dump_timing_advert(struct libwifi_timing_advert *adv, unsigned char *buf, size_t buf_len) {
    size_t adv_len = libwifi_get_timing_advert_length(adv);
    if (adv_len > buf_len) {
        return -1;
    }

    size_t offset = 0;
    memcpy(buf + offset, &adv->frame_header, sizeof(struct libwifi_mgmt_unordered_frame_header));
    offset += sizeof(struct libwifi_mgmt_unordered_frame_header);

    memcpy(buf + offset, &adv->fixed_parameters, sizeof(struct libwifi_timing_advert_fixed_params));
    offset += sizeof(struct libwifi_timing_advert_fixed_params);

    memcpy(buf + offset, adv->tags.parameters, adv->tags.length);
    offset += adv->tags.length;

    return adv_len;
}

void libwifi_free_timing_advert(struct libwifi_timing_advert *adv) {
    free(adv->tags.parameters);
}
