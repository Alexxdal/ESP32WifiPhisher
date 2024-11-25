#ifndef _VENDORS_H
#define _VENDORS_H


#include "esp_system.h"

typedef enum {
    GENERIC = 0x00,
    VODAFONE,
    FASTWEB,
    TPLINK,
    TIM,
    DLINK,
    SKYWIFI,
    WIND,
    LINKEM,
    HUAWEI,
    NETGER,
    TISCALI,
    FRITZBOX,
    NETIS
} vendors_t;


typedef struct {
    const char *uri;
    const char *logo;
    size_t logo_size;
} logo_entry_t;


/**
 * @brief Get vendor from ssid
 * 
 * @param ssid 
 * @return vendors_t 
 */
vendors_t getVendor(char *ssid);


/**
 * @brief Return the vendor string
 * 
 * @param vendor 
 * @return const char* 
 */
const char * vendorToString(vendors_t vendor);


#endif
