#ifndef _KARMA_ATTACK_H
#define _KARMA_ATTACK_H

#include "target.h"

typedef enum {
    KARMA_ATTACK_STATUS_IDLE = 0,
    KARMA_ATTACK_STATUS_PROBE_SCANNING,
    KARMA_ATTACK_STATUS_SOFTAP,
    KARMA_ATTACK_STATUS_MAX
} karma_attack_status_t;


/**
 * @brief Start KARMA attack probe scan.
 * 
 */
void karma_attack_probes_scan_start(void);


/**
 * @brief Stop KARMA attack probe scan.
 * 
 */
void karma_attack_probes_scan_stop(void);


/**
 * @brief Set the target for KARMA attack.
 * 
 * @param target Pointer to target_info_t structure containing target details.
 */
void karma_attack_set_target(const target_info_t *target);


/**
 * @brief Stop the KARMA attack.
 * 
 */
void karma_attack_stop(void);


/**
 * @brief Get current karma attack status
 * 
 */
karma_attack_status_t karma_attack_get_status(void);


/**
 * @brief Convert karma attack status to string
 * 
 */
const char* karma_attack_get_status_string(void);

#endif