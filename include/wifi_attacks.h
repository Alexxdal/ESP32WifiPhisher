#ifndef _WIFI_ATTACKS_H
#define _WIFI_ATTACKS_H

/**
 * @brief Basic Deauthentication Attack.
 * 
 */
esp_err_t wifi_attack_deauth_basic(const uint8_t dest[6], const uint8_t bssid[6], uint8_t reason_code);


/**
 * @brief Send Disassociation frame
 */
esp_err_t wifi_attack_send_disassoc(const uint8_t bssid[6], const uint8_t dest[6], uint8_t reason);


/**
 * @brief Send Authentication frame (Open System)
 */
esp_err_t wifi_attack_send_auth_frame(const uint8_t bssid[6], const uint8_t src_mac[6]);


/**
 * @brief Send Association Request frame
 */
esp_err_t wifi_attack_send_assoc_req(const uint8_t bssid[6], const uint8_t src_mac[6]);


/**
 * @brief Send Beacon with CSA (Channel Switch Announcement) IE
 */
esp_err_t wifi_attack_send_csa_beacon(const uint8_t bssid[6], const uint8_t src_mac[6], uint8_t new_channel);


/**
 * @brief Deauthentication using invalid PMKID Tag Length in 4-Way Handshake 1/4.
 * @note
 * The EAPoL Key Descriptor needs to match the original 4-Way Handshake 1/4:
 * For other network configurations, you might need to change byte 0x88 of
 * the EAPoL-frame to the approratie value. For WPA2-Personal-PMF: 0x8a.
 * Attack in fact works with an underflow in any tag, not just the PMKID.
 * 
 */
esp_err_t wifi_attack_deauth_client_invalid_PMKID(const uint8_t client[6], const uint8_t bssid[6]);


/**
 * @brief Inject a 4-way message 1 frame that also has the Install flag set.
 * 
 */
esp_err_t wifi_attack_deauth_client_bad_msg1(const uint8_t client[6], const uint8_t bssid[6], const wifi_auth_mode_t authmode);


/**
 * @brief Client sends spoofed association request to the AP with the sleep bit set.
 * networks with PMF enabled sends and association failure response to the client and 
 * and an SA Query Request but becuase the sleep bit this frame is buffered and never sent 
 * causing a timeout that will cause the client to disconnect.
 * 
 */
esp_err_t wifi_attack_association_sleep(const uint8_t client[6], const uint8_t bssid[6], const char *ssid);


/**
 * @brief Deauthentication using an EAPOL-Logoff.
 * 
 */
esp_err_t wifi_attack_deauth_ap_eapol_logoff(const uint8_t client[6], const uint8_t bssid[6]);


/**
 * @brief Deauthentication using an EAP-Failure.
 * 
 */
esp_err_t wifi_attack_deauth_client_eap_failure(const uint8_t client[6], const uint8_t bssid[6]);


/**
 * @brief Deauthentication using an excessive number of EAP Rounds.
 * 
 */
esp_err_t wifi_attack_deauth_client_eap_rounds(const uint8_t client[6], const uint8_t bssid[6]);


/**
 * @brief Deauthentication using EAPOL-Starts.
 * 
 */
esp_err_t wifi_attack_deauth_ap_eapol_start(const uint8_t client[6], const uint8_t bssid[6]);


/**
 * @brief Send beacon frame with negative tx power
 * some device may disconnect
 * 
 */
esp_err_t wifi_attack_deauth_client_negative_tx_power(const uint8_t bssid[6], uint8_t channel, const char *ssid);


/**
 * @brief Spam softAP beacon from STA
 * 
 * @param target 
 */
esp_err_t wifi_attack_softap_beacon_spam(const char *ssid, uint8_t channel);


/**
 * @brief Send a Karma-style probe response to a victim device.
 * 
 * @param victim_mac MAC address of the victim device.
 * @param requested_ssid SSID requested by the victim device.
 * @param channel Channel to send the probe response on.
 */
esp_err_t wifi_attack_send_karma_probe_response(const uint8_t *victim_mac, const char *requested_ssid, uint8_t channel);


/**
 * @brief Attempts to perform a NAV (Network Allocation Vector) Abuse attack using RTS frames.
 * * This function constructs an RTS (Request-to-Send) Control frame with the Duration ID 
 * set to the maximum value (0x7FFF, approx 32ms) to reserve the RF medium.
 * * @param bssid The target Access Point BSSID (used as Receiver Address).
 * * @warning **NOT EFFECTIVE ON ESP32**. 
 * The ESP32 Wi-Fi hardware MAC layer identifies frames with Type: Control (0x1) 
 * and Subtype: RTS (0xB). It automatically recalculates and overwrites the 
 * Duration field based on the current PHY rate and packet length, ignoring 
 * the user-supplied value (0x7FFF).
 */
esp_err_t wifi_attack_nav_abuse_rts(const uint8_t bssid[6]);


/**
 * @brief Attempts to perform a NAV Abuse attack using CTS frames (CTS-to-Self).
 * * This function constructs a CTS (Clear-to-Send) Control frame with the Duration ID 
 * set to the maximum value (0x7FFF) to silence all nearby nodes.
 * * @param bssid The MAC address to simulate (usually the BSSID for CTS-to-Self).
 * * @warning **NOT EFFECTIVE ON ESP32**. 
 * Similar to the RTS attack, the ESP32 hardware controller intercepts CTS Control 
 * frames and overrides the Duration field with the standard calculated value 
 * (required time for SIFS + ACK), neutralizing the DoS attempt.
 */
esp_err_t wifi_attack_nav_abuse_cts(const uint8_t bssid[6]);


/**
 * @brief Executes a functional NAV Abuse attack using QoS Null Data frames.
 * * This function bypasses the ESP32 hardware protections by using a DATA frame 
 * (Type: 0x2, Subtype: 0xC - QoS Null) instead of a Control frame. 
 * The hardware allows user-defined Duration values for Data frames.
 * * @param target The MAC address of the victim client (or FF:FF:FF:FF:FF:FF for broadcast).
 * @param bssid The BSSID of the Access Point.
 * * * @warning **NOT EFFECTIVE ON ESP32**. 
 * The ESP32 Wi-Fi hardware MAC layer automatically recalculates and overwrites the 
 * Duration field based on the current PHY rate and packet length, ignoring 
 * the user-supplied value (0x7FFF).
 */
esp_err_t wifi_attack_nav_abuse_qos_null(const uint8_t target[6], const uint8_t bssid[6]);


/**
 * @brief Performs a NAV (Network Allocation Vector) Abuse attack using QoS Data frames.
 * * This function constructs a QoS Data frame (Type: 0x2, Subtype: 0x8) injected with a 
 * maximized Duration ID (0x7FFF, approx 32ms). This forces receiving devices to 
 * update their NAV timers and suspend transmission, virtually jamming the network.
 * * @param target The MAC address of the victim (Source/Transmitter).
 * @param bssid The BSSID of the Access Point (Receiver/Destination).
 * * @note The efficacy of this attack on ESP32 depends on whether the hardware MAC layer 
 * respects the user-defined Duration field for Unicast Data frames. If the hardware 
 * overwrites it, using a Broadcast Receiver address is the recommended bypass.
 * * @warning **NOT EFFECTIVE ON ESP32**. 
 */
esp_err_t wifi_attack_nav_abuse_qos_data(const uint8_t target[6], const uint8_t bssid[6]);


/**
 * @brief Performs a NAV Abuse attack using QoS Data frames directed to Broadcast.
 * @details This approach bypasses the ESP32 hardware duration overwrite by targeting the 
 * Broadcast address (FF:FF:FF:FF:FF:FF). Since Broadcast frames do not require 
 * an ACK, the hardware MAC layer does not recalculate the Duration field, allowing 
 * the injection of the maximum value (0x7FFF / ~32ms).
 * * @param ap_bssid The BSSID of the Access Point to spoof (Source address).
 * * @warning **NOT EFFECTIVE ON ESP32**. 
 */
esp_err_t wifi_attack_nav_abuse_qos_data_broadcast(const uint8_t ap_bssid[6]);


/**
 * @brief Floods the AP with WPA3 SAE Commit frames to exhaust CPU resources.
 * @param bssid Target AP BSSID
 */
esp_err_t wifi_attack_wpa3_sae_flood(const uint8_t bssid[6]);

#endif