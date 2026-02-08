#ifndef _EVIL_TWIN_H
#define _EVIL_TWIN_H

#include "target.h"

typedef enum {
    EVIL_TWIN_ATTACK_STATUS_IDLE = 0,
    EVIL_TWIN_ATTACK_STATUS_ACTIVE,
    EVIL_TWIN_ATTACK_STATUS_MAX
} evil_twin_attack_status_t;


typedef struct {
    uint64_t packet_sent_2ghz;
    uint64_t packet_sent_5ghz;
    bool has_5ghz_target;
    evil_twin_attack_status_t current_status;
} evil_twin_attack_status_info_t;


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


/**
 * @brief Get current Evil Twin attack status
 * 
 */
evil_twin_attack_status_t evil_twin_attack_get_status(void);


/**
 * @brief Convert Evil Twin attack status to string
 * 
 */
const char* evil_twin_attack_get_status_string(void);


/**
 * @brief Get Evil Twin detailed status
 */
const evil_twin_attack_status_info_t* evil_twin_attack_get_status_info(void);

#endif