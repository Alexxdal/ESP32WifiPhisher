#ifndef _SNIFFER_H
#define _SNIFFER_H

#include "target.h"

#define CLIENT_SEM_WAIT 10
#define TARGET_SEM_WAIT 10



/**
 * @brief List of APs using native ESP-IDF struct
 * 
 */
#define MAX_AP      35
typedef struct {
    uint8_t count;
    wifi_ap_record_t ap[MAX_AP];
} aps_info_t;



/**
 * @brief Struct containing Client info
 * 
 */
#define MAX_CLIENTS 50
typedef struct {
    uint8_t mac[6];     //Client MAC
    uint8_t bssid[6];   //Associated AP
} client_t;

typedef struct {
    uint8_t count;
    client_t client[MAX_CLIENTS];
} client_list_t;



/**
 * @brief Struct containing captured probe request info
 * 
 */
#define MAX_PROBE_REQ   30
typedef struct {
    uint8_t mac[6];
    char ssid[33];
    int8_t rssi;
    uint8_t channel;
} probe_request_t;

typedef struct {
    uint8_t num_probes;
    probe_request_t probes[MAX_PROBE_REQ];
} probe_request_list_t;



/**
 * @brief Struct containing captured HANDSHAKE and PMKID for aircrack
 * 
 */
#define MAX_HANDSHAKE_NUM 10
typedef struct {
    uint8_t bssid[6];
    uint8_t mac_sta[6];
    uint8_t anonce[32];
    uint8_t snonce[32];
    uint8_t mic[16];
    uint8_t pmkid[16];
    uint8_t eapol[256];
    uint16_t eapol_len;
    uint8_t key_decriptor_version;
    /* Capture information */
    int64_t last_m1_timestamp;
    uint64_t replay_counter;
    bool handshake_captured;
    bool pmkid_captured;
} handshake_info_t;

typedef struct {
    uint8_t count;
    handshake_info_t handshake[MAX_HANDSHAKE_NUM];
} handshake_info_list_t;



/**
 * @brief Struct containing a sniffed packet
 */
#define PACKET_MAX_PAYLOAD_LEN 400
typedef struct {
    uint8_t payload[PACKET_MAX_PAYLOAD_LEN];
    uint16_t length;
    int8_t rssi;
    uint8_t channel;
} sniffer_packet_t;



/**
 * @brief Start packet sniffing in promiscuous mode
 * 
 * @return esp_err_t 
 */
esp_err_t wifi_start_sniffing(void);


/**
 * @brief Stop packet sniffing in promiscuous mode
 * 
 * @return esp_err_t 
 */
esp_err_t wifi_stop_sniffing(void);


/**
 * @brief Set filter for promiscous mode
 * 
 * @param type Main type (MGMT, DATA, CONTROL)
 * @param subtype Filter subtype
 * @param channel Set to 0 to disable filter
 */
void wifi_sniffer_set_fine_filter(int type, uint32_t subtype, uint8_t channel);


/**
 * @brief Set sniffer BSSID filter
 */
void wifi_sniffer_set_bssid_filter(uint8_t *bssid);


/**
 * @brief Start channel hopping task
 * 
 * @param channel Target channel to temporary switch
 * @return esp_err_t 
 */
esp_err_t wifi_sniffer_start_channel_hopping(uint8_t channel);


/**
 * @brief Stop channel hopping task
 * 
 * @return esp_err_t 
 */
esp_err_t wifi_sniffer_stop_channel_hopping(void);


/**
 * @brief Set live packet analyzer to send raw frame information over websocket
 * 
 */
void wifi_sniffer_start_packet_analyzer(bool start);


/**
 * @brief Get copy of captured probe requests list
 * * @param out Pointer to destination structure
 * @return esp_err_t 
 */
esp_err_t wifi_sniffer_get_probes(probe_request_list_t *out);


/**
 * @brief Get pointer to captured handshake info
 * 
 * @return const handshake_info_t* 
 */
esp_err_t wifi_sniffer_get_handshake_for_target(const uint8_t *bssid, const uint8_t *client_mac, handshake_info_t *out);


/**
 * @brief Check if there is and handshake or PMKID for target
 * 0 = None, 1 = handshake, 2 = PMKID, 3 = Both
 */
int wifi_sniffer_get_handshake_status_for_target(const uint8_t *bssid);


/**
 * @brief Get pointer to detected clients info
 * 
 * @return const clients_t* 
 */
esp_err_t wifi_sniffer_get_clients(client_list_t *out);


/**
 * @brief Return the number of captured clients/STA
 * 
 */
uint8_t wifi_sniffer_get_clients_count(void);


/**
 * @brief Get pointer to detected aps info
 * 
 * @return const aps_info_t* 
 */
esp_err_t wifi_sniffer_get_aps(aps_info_t *out);


/**
 * @brief Return the number of detected APs
 * 
 */
uint8_t wifi_sniffer_get_aps_count(void);


/**
 * @brief Scan for aps and fill static memory
 */
esp_err_t wifi_sniffer_scan_fill_aps(void);

#endif /* _SNIFFER_H */