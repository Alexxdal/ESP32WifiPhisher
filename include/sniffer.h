#ifndef _SNIFFER_H
#define _SNIFFER_H

#include "target.h"

#define PACKET_MAX_PAYLOAD_LEN 352

#define CLIENT_SEM_WAIT 10
#define TARGET_SEM_WAIT 10
#define MAX_PROBE_REQ   30

/**
 * @brief Number of max client to store
 * 
 */
#define MAX_CLIENTS 50


/**
 * @brief Number of max ap to store
 * 
 */
#define MAX_AP      35


/**
 * @brief Sniffer operating modes
 * 
 */
typedef enum {
    SNIFF_MODE_IDLE = 0,        // Sniffer fermo o promiscuo disabilitato
    SNIFF_MODE_GLOBAL_MONITOR,  // Ascolta tutto (Scan, statistiche generali)
    SNIFF_MODE_TARGET_ONLY,     // Ascolta SOLO il target (Handshake/PMKID capture, no attacchi)
    SNIFF_MODE_ATTACK_KARMA,    // Risponde alle Probe Requests (Karma)
    SNIFF_MODE_ATTACK_EVIL_TWIN,// Logica Evil Twin (Deauth + Monitoraggio specifico)
    SNIFF_MODE_RAW_VIEW,        // Logica per packet analyzer
    SNIFF_MODE_MAX
} sniffer_mode_t;


/**
 * @brief List of APs using native ESP-IDF struct
 * 
 */
typedef struct {
    uint8_t count;
    wifi_ap_record_t ap[MAX_AP]; // Array nativo
} aps_info_t;


/**
 * @brief Struct containing Client info
 * 
 */
typedef struct {
    uint8_t mac[6];     //Client MAC
    uint8_t bssid[6];   //Associated AP
} client_t;


/**
 * @brief List of associated client to the target AP
 * 
 */
typedef struct {
    uint8_t count;
    client_t client[MAX_CLIENTS];
} clients_t;


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
    uint8_t channel;
} sniffer_packet_t;


/**
 * @brief Struct containing captured probe request info
 * 
 */
typedef struct {
    uint8_t mac[6];
    char ssid[33];
    int8_t rssi;
    uint8_t channel;
} probe_request_t;


/**
 * @brief Struct containing list of captured probe requests
 * 
 */
typedef struct {
    uint8_t num_probes;
    probe_request_t probes[MAX_PROBE_REQ];
} probe_request_list_t;


/**
 * @brief Start packet sniffing in promiscuous mode
 * 
 * @param _target 
 * @param mode 
 * @return esp_err_t 
 */
esp_err_t wifi_start_sniffing(target_info_t * _target, sniffer_mode_t mode);


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
 * @brief Set sniffer operating mode
 * 
 * @param mode 
 */
void wifi_sniffer_set_mode(sniffer_mode_t mode);


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
 * @brief Get pointer to captured probe requests
 * 
 * @return const probe_request_list_t*
 */
const probe_request_list_t *wifi_sniffer_get_captured_probes(void);


/**
 * @brief Get pointer to captured handshake info
 * 
 * @return const handshake_info_t* 
 */
const handshake_info_t * wifi_sniffer_get_handshake(void);


/**
 * @brief Get pointer to detected clients info
 * 
 * @return const clients_t* 
 */
esp_err_t wifi_sniffer_get_clients(clients_t *out);


/**
 * @brief Get pointer to detected aps info
 * 
 * @return const aps_info_t* 
 */
esp_err_t wifi_sniffer_get_aps(aps_info_t *out);


/**
 * @brief Scan for aps and fill static memory
 */
esp_err_t wifi_sniffer_scan_fill_aps(void);

#endif /* _SNIFFER_H */