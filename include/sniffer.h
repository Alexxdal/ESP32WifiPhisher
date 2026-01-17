#ifndef _SNIFFER_H
#define _SNIFFER_H

#include "esp_system.h"
#include "wifi_attacks.h"

#define PACKET_MAX_PAYLOAD_LEN 352

/* Tasks Priority and queue len */
#define BEACON_TRACK_TASK_PRIO        10
#define PACKET_PARSING_TASK_PRIO      5
#define PACKET_QUEUE_LEN              25

#define CLIENT_SEM_WAIT 10
#define TARGET_SEM_WAIT 10

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
 * @brief Struct containing a sniffed packet
 */
typedef struct {
    uint8_t payload[PACKET_MAX_PAYLOAD_LEN];
    uint16_t length;
    int8_t rssi;
} sniffer_packet_t;


/**
 * @brief Start packet sniffing in promiscuous mode
 * 
 * @param _target 
 * @return esp_err_t 
 */
esp_err_t wifi_start_sniffing(target_info_t *_target);


/**
 * @brief Stop packet sniffing in promiscuous mode
 * 
 * @return esp_err_t 
 */
esp_err_t wifi_stop_sniffing(void);


/**
 * @brief Start beacon tracking for channel hopping
 * 
 * @return esp_err_t 
 */
esp_err_t wifi_start_beacon_tracking(void);


/**
 * @brief Stop beacon tracking for channel hopping
 * 
 * @return esp_err_t 
 */
esp_err_t wifi_stop_beacon_tracking(void);


/**
 * @brief Get pointer to captured handshake info
 * 
 * @return const handshake_info_t* 
 */
const handshake_info_t * wifi_sniffer_get_handshake(void);


#endif /* _SNIFFER_H */