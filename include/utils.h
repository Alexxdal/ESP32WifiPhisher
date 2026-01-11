#ifndef _UTILS_H
#define _UTILS_H

#include <esp_system.h>
#include "libwifi.h"
#include "wifi_attacks.h"


/**
 * @brief Check if a MAC Address is broadcast
 * 
 * @param mac 
 * @return true 
 * @return false 
 */
bool isMacBroadcast(const uint8_t *mac);


/**
 * @brief Check if a MAC Address is Zero
 * 
 * @param mac 
 * @return true 
 * @return false 
 */
bool isMacZero(uint8_t *mac);


/**
 * @brief Check if two MAC Addresses are equal
 * 
 * @param mac1 
 * @param mac2 
 * @return true 
 * @return false 
 */
bool isMacEqual(const uint8_t *mac1, const uint8_t *mac2);


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


/**
 * @brief Get the Next Channel
 * 
 * @param current_channel 
 * @return uint8_t 
 */
uint8_t getNextChannel(uint8_t current_channel);


/**
 * @brief Convert wifi_auth_mode_t to string
 * 
 * @param m 
 * @return const char* 
 */
const char *authmode_to_str(wifi_auth_mode_t m);


/**
 * @brief Find EAPOL frame in buffer
 * 
 * @param buffer 
 * @param len 
 * @param eapol_len 
 * @return uint8_t
 */
uint8_t *find_eapol_frame(uint8_t *buffer, uint16_t len, uint16_t *eapol_len);

#endif