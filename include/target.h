#ifndef _TARGET_H
#define _TARGET_H

#include "esp_system.h"
#include "esp_wifi.h"
#include "vendors.h"


typedef enum {
    TARGET_INFO_EVIL_TWIN = 0x00,
    TARGET_INFO_KARMA_ATTACK,
    TARGET_INFO_MAX
} target_info_type_t;


/**
 * @brief Struct containing the current target
 * 
 */
typedef struct {
    uint8_t bssid[6];
    uint8_t ssid[33];
    wifi_auth_mode_t authmode;
    wifi_cipher_type_t pairwise_cipher;
    wifi_cipher_type_t group_cipher;
    int8_t rssi;
    uint8_t channel;
    vendors_t vendor;
    uint8_t attack_scheme;
} target_info_t;


/**
 * @brief Set the current target
 * 
 * @param target Pointer to the target_info_t struct
 * @param type Type of target_info_t
 */
void target_set(const target_info_t *target, target_info_type_t type);


/**
 * @brief Get the current target
 * 
 * @param type Type of target_info_t
 * @return target_info_t* Pointer to the target_info_t struct
 */
target_info_t* target_get(target_info_type_t type);


#endif /* _TARGET_H */