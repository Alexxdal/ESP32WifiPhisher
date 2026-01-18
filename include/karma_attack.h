#ifndef _KARMA_ATTACK_H
#define _KARMA_ATTACK_H

#include "target.h"

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

#endif