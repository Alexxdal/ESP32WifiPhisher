#ifndef _UTILS_H
#define _UTILS_H

#include <esp_system.h>
#include "libwifi.h"
#include "wifi_attacks.h"

/**
 * @brief Print packet bytes
 * 
 * @param data 
 * @param len 
 */
void print_packet(uint8_t *data, size_t len);


/**
 * @brief Print buffer data
 * 
 * @param buffer 
 * @param len 
 */
void print_buffer(uint8_t *buffer, size_t len);


/**
 * @brief Print handshake information
 * 
 * @param handshake 
 */
void print_handshake(handshake_info_t *handshake);


/**
 * @brief Dump wifi auth data into buffer
 * 
 * @param auth_data 
 * @param buffer 
 * @param buffer_len 
 * @return size_t 
 */
size_t libwifi_dump_wpa_auth_data(struct libwifi_wpa_auth_data *auth_data, uint8_t *buffer, size_t buffer_len);


#endif