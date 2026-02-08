#ifndef DEAUTHER_H
#define DEAUTHER_H

#include <stdint.h>
#include <stdbool.h>
#include "target.h"


/**
 * @brief Deauther attack modes
 */
typedef enum {
    // 0 - Deauthentication frame (Classic)
    DEAUTHER_ATTACK_DEAUTH_FRAME       = 0,
    // 1 - Disassociation frame (Forced)
    DEAUTHER_ATTACK_DISASSOC_FRAME     = 1,
    // 2 - Broadcast deauth/disassoc
    DEAUTHER_ATTACK_BROADCAST_FLOOD    = 2,
    // 3 - Authentication flood
    DEAUTHER_ATTACK_AUTH_FLOOD         = 3,
    // 4 - Association/Reassociation flood
    DEAUTHER_ATTACK_ASSOC_FLOOD        = 4,
    // 5 - CSA spoofing (Channel Switch Announcement)
    DEAUTHER_ATTACK_CSA_SPOOFING       = 5,
    // 6 - EAPOL-Logoff spoofing
    DEAUTHER_ATTACK_EAPOL_LOGOFF       = 6,
    // 7 - EAPOL-Start spam
    DEAUTHER_ATTACK_EAPOL_START        = 7,
    // 8 - EAP Failure injection
    DEAUTHER_ATTACK_EAP_FAILURE        = 8,
    // 9 - EAP Identity request spam / rounds abuse
    DEAUTHER_ATTACK_EAP_ID_SPAM        = 9,
    // 10 - 4-Way Handshake disruption
    DEAUTHER_ATTACK_HANDSHAKE_BLOCK    = 10,
    // 11 - WPA3 SAE flood
    DEAUTHER_ATTACK_WPA3_SAE_FLOOD     = 11,
    // 12 - PMF/802.11w downgrade pressure
    DEAUTHER_ATTACK_PMF_DOWNGRADE      = 12,
    // 13 - NAV/RTS/CTS abuse
    DEAUTHER_ATTACK_NAV_ABUSE          = 13,
    // 14 - Beacon manipulation
    DEAUTHER_ATTACK_BEACON_SPAM        = 14,
    DEAUTHER_ATTACK_MAX
} deauther_attack_type_t;


/**
 * @brief Deauther attack target mode
 */
typedef enum {
    DEAUTHER_TARGET_UNICAST = 0,
    DEAUTHER_TARGET_ALL
} deauther_attack_mode_t;


/**
 * @brief Start deauthentication attack on target
 * @param deauth_target deauth attack target
 * 
 */
void deauther_start(const target_info_t *deauth_target, deauther_attack_type_t attack_type);


/**
 * @brief Stop deauthentication attack
 * 
 */
void deauther_stop(void);


bool deauther_is_running(void);

#endif // DEAUTHER_H