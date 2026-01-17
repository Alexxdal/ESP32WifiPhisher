#ifndef _WIFI_ATTACKS_H
#define _WIFI_ATTACKS_H

#include "esp_system.h"
#include "esp_wifi.h"
#include "vendors.h"


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
 * @brief Basic Deauthentication Attack.
 * 
 */
void wifi_attack_deauth_basic(const uint8_t dest[6], const uint8_t bssid[6], uint8_t reason_code);


/**
 * @brief Deauthentication using invalid PMKID Tag Length in 4-Way Handshake 1/4.
 * @note
 * The EAPoL Key Descriptor needs to match the original 4-Way Handshake 1/4:
 * For other network configurations, you might need to change byte 0x88 of
 * the EAPoL-frame to the approratie value. For WPA2-Personal-PMF: 0x8a.
 * Attack in fact works with an underflow in any tag, not just the PMKID.
 * 
 */
void wifi_attack_deauth_client_invalid_PMKID(const uint8_t client[6], const uint8_t bssid[6]);


/**
 * @brief Inject a 4-way message 1 frame that also has the Install flag set.
 * 
 */
void wifi_attack_deauth_client_bad_msg1(const uint8_t client[6], const uint8_t bssid[6], const wifi_auth_mode_t authmode);


/**
 * @brief Client sends spoofed association request to the AP with the sleep bit set.
 * networks with PMF enabled sends and association failure response to the client and 
 * and an SA Query Request but becuase the sleep bit this frame is buffered and never sent 
 * causing a timeout that will cause the client to disconnect.
 * 
 */
void wifi_attack_association_sleep(const uint8_t client[6], const uint8_t bssid[6], const char *ssid);


/**
 * @brief Deauthentication using an EAPOL-Logoff.
 * 
 */
void wifi_attack_deauth_ap_eapol_logoff(const uint8_t client[6], const uint8_t bssid[6]);


/**
 * @brief Deauthentication using an EAP-Failure.
 * 
 */
void wifi_attack_deauth_client_eap_failure(const uint8_t client[6], const uint8_t bssid[6]);


/**
 * @brief Deauthentication using an excessive number of EAP Rounds.
 * 
 */
void wifi_attack_deauth_client_eap_rounds(const uint8_t client[6], const uint8_t bssid[6]);


/**
 * @brief Deauthentication using EAPOL-Starts.
 * 
 */
void wifi_attack_deauth_ap_eapol_start(const uint8_t client[6], const uint8_t bssid[6]);


/**
 * @brief Send beacon frame with negative tx power
 * some device may disconnect
 * 
 */
void wifi_attack_deauth_client_negative_tx_power(const uint8_t bssid[6], uint8_t channel, const char *ssid);


/**
 * @brief Spam softAP beacon from STA
 * 
 * @param target 
 */
void wifi_attack_softap_beacon_spam(const char *ssid, uint8_t channel);

#endif