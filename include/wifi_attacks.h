#ifndef _WIFI_ATTACKS_H
#define _WIFI_ATTACKS_H

#include "esp_system.h"
#include "esp_wifi.h"
#include "vendors.h"

/**
 * @brief Number of max client to store
 * 
 */
#define MAX_CLIENTS 20

/**
 * @brief List of associated client to the target AP
 * 
 */
typedef struct {
    uint8_t mac[6];
} client_t;


/**
 * @brief Struct containing the current evil twin target
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
 * @brief Struct containing captured HANDSHAKE and PMKID for aircrack
 * 
 */
typedef struct {
    uint8_t mac_sta[6];
    uint8_t anonce[32];
    uint8_t snonce[32];
    uint8_t mic[16];
    uint8_t pmkid[16];
    uint8_t eapol[256];
    uint16_t eapol_len;
    uint8_t key_decriptor_version;
    bool handshake_captured;
    bool pmkid_captured;
} handshake_info_t;


/**
 * @brief Initialize the attack engine
 * 
 */
void wifi_attack_engine_start(target_info_t *_target);


/**
 * @brief Stop attack engine and clean variables
 * 
 */
void wifi_attack_engine_stop(void);


/**
 * @brief Deauth attack by sending deauth frames 
 * 
 * @param bssid 
 */
void wifi_attack_deauth_basic(void);


/**
 * @brief Deauthentication using invalid PMKID Tag Length in 4-Way Handshake 1/4.
 * @note
 * The EAPoL Key Descriptor needs to match the original 4-Way Handshake 1/4:
 * For other network configurations, you might need to change byte 0x88 of
 * the EAPoL-frame to the approratie value. For WPA2-Personal-PMF: 0x8a.
 * Attack in fact works with an underflow in any tag, not just the PMKID.
 * 
 */
void wifi_attack_deauth_client_invalid_PMKID(void);


/**
 * @brief Inject a 4-way message 1 frame that also has the Install flag set.
 * 
 */
void wifi_attack_deauth_client_bad_msg1(void);


/**
 * @brief Client sends spoofed association request to the AP with the sleep bit set.
 * networks with PMF enabled sends and association failure response to the client and 
 * and an SA Query Request but becuase the sleep bit this frame is buffered and never sent 
 * causing a timeout that will cause the client to disconnect.
 * 
 */
void wifi_attack_association_sleep(void);


/**
 * @brief Deauthentication using an EAPOL-Logoff.
 * 
 */
void wifi_attack_deauth_ap_eapol_logoff(void);


/**
 * @brief Deauthentication using an EAP-Failure.
 * 
 */
void wifi_attack_deauth_client_eap_failure(void);


/**
 * @brief Deauthentication using an excessive number of EAP Rounds.
 * 
 */
void wifi_attack_deauth_client_eap_rounds(void);


/**
 * @brief Deauthentication using EAPOL-Starts.
 * 
 */
void wifi_attack_deauth_ap_eapol_start(void);


/**
 * @brief Send beacon frame with negative tx power
 * some device may disconnect
 * 
 */
void wifi_attack_deauth_client_negative_tx_power(void);


/**
 * @brief Spam softAP beacon from STA
 * 
 * @param target 
 */
void wifi_attack_softap_beacon_spam(target_info_t *_target);


/**
 * @brief Get captured handshake and pmkid
 * 
 *
 */
handshake_info_t * wifi_attack_engine_handshake(void);


#endif