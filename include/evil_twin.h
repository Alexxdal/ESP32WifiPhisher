#ifndef _EVIL_TWIN_H
#define _EVIL_TWIN_H

#include "esp_wifi.h"
#include "esp_system.h"
#include "vendors.h"
#include "wifi_attacks.h"
#include "target.h"


/**
 * @brief Start EVIL TWIN attack, before lauching be sure to fill target struct
 * 
 */
void evil_twin_start_attack(const target_info_t *targe_info);


/**
 * @brief Stop EVIL TWIN attack.
 * 
 */
void evil_twin_stop_attack(void);


/**
 * @brief Check the user input password
 * 
 * @param password 
 * @return bool
 */
bool evil_twin_check_password(char *password);

#endif