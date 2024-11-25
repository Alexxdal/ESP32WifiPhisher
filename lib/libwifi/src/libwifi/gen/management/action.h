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

#ifndef LIBWIFI_GEN_ACTION_H
#define LIBWIFI_GEN_ACTION_H

#include "../../core/frame/management/action.h"
#include <stdint.h>

/**
 * Create a detail for an action frame by supplying raw data and it's length.
 * New data can be added to an existing libwifi_action_detail.
 *
 * @param detail   A libwifi_action_detail struct
 * @param data     Raw data to be added to the libwifi_action_detail
 * @param data_len Length of the raw data
 * @return         Length of the action, or negative error
 */
size_t libwifi_add_action_detail(struct libwifi_action_detail *detail,
                                 const unsigned char *data,
                                 size_t data_len);

/**
 * Free all memory in a given libwifi_action_detail.
 *
 * @param detail A used libwifi_action_detail struct
 */
void libwifi_free_action_detail(struct libwifi_action_detail *detail);

/**
 * Create a new action frame with a specified action and category.
 *
 * @param action      A new libwifi_action struct
 * @param receiver    The receiver MAC address
 * @param transmitter The transmitter MAC address
 * @param address3    The address 3 frame field value, typically the BSSID
 * @param category    The action frame category
 * @return            Zero on success, or negative error
 */
int libwifi_create_action(struct libwifi_action *action,
                          const unsigned char receiver[6],
                          const unsigned char transmitter[6],
                          const unsigned char address3[6],
                          uint8_t category);
int libwifi_create_action_no_ack(struct libwifi_action *action,
                                 const unsigned char receiver[6],
                                 const unsigned char transmitter[6],
                                 const unsigned char address3[6],
                                 uint8_t category);

/**
 * Get the length of a given libwifi_action
 *
 * @param  action A used libwifi_action struct
 * @return        The length of the given libwifi_action
 */
size_t libwifi_get_action_length(struct libwifi_action *action);

/**
 * Dump a given libwifi_action to a raw buffer
 *
 * @param  action  A used libwifi_action struct
 * @param  buf     A buffer receiver
 * @param  buf_len The length of the given buf
 * @return         Bytes written to the buf, or negative error
 */
size_t libwifi_dump_action(struct libwifi_action *action, unsigned char *buf, size_t buf_len);

/**
 * Free data associated to a given libwifi_action
 *
 * @param action A used libwifi_action struct
 */
void libwifi_free_action(struct libwifi_action *action);

#endif /* LIBWIFI_GEN_ACTION_H */
