#ifndef _UTILS_H
#define _UTILS_H

#include <esp_system.h>
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


#endif