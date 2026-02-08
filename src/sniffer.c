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
#include "evil_twin.h"
#include "karma_attack.h"
#include "deauther.h"

#define HANDSHAKE_TIMEOUT_US 2000000 // 2 Seconds timeout between M1 and M2

static const char *TAG = "SNIFFER";

/* Tasks Priority and queue len */
#define PACKET_PARSING_TASK_PRIO            10
#define PACKET_QUEUE_LEN                    50
#define CHANNEL_HOPPING_TASK_PRIO           3

/* Queue and semaphore */
static QueueHandle_t packet_queue = NULL;
static SemaphoreHandle_t clients_semaphore = NULL;
static SemaphoreHandle_t aps_semaphore = NULL;
static SemaphoreHandle_t handshake_semaphore = NULL;
static SemaphoreHandle_t probes_semaphore = NULL;

/* Tasks handlers */
static TaskHandle_t packet_parsing_task_handle = NULL;
static TaskHandle_t channel_hopping_task_handle = NULL;

/* Group Bits */
#define SCAN_DONE_BIT (1<<0)
#define ROC_DONE_BIT (1<<0)
static EventGroupHandle_t scan_evt = NULL;
static EventGroupHandle_t roc_evt = NULL;
static esp_event_handler_instance_t scan_done_event_instance = NULL;
static esp_event_handler_instance_t roc_done_event_instance = NULL;

/* Client and target info */
static client_list_t clients = {0};
static handshake_info_list_t captured_handshakes = {0};
static probe_request_list_t captured_probes = {0};
static aps_info_t detected_aps = {0};

/* Filters for promiscous mode */
static int filter_type_main = 0;
static uint32_t filter_subtype_mask = 0;
static uint8_t filter_channel = 0;
static uint8_t filter_bssid[6] = {0};
static bool filter_bssid_enabled = false;
static bool live_packet_analyzer = false;

/* Callback */
sniffer_packet_t callback_sniffer_pkt = {0};

/* Private function */
static void add_client_to_list(const uint8_t *mac, const uint8_t *bssid);
static void wifi_sniffer_channel_hopping_task(void *param);


static void wifi_event_scan_done_handler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data)
{
    if(event_base != WIFI_EVENT) return;
    if (event_id == WIFI_EVENT_SCAN_DONE) 
    {
        if(scan_evt) xEventGroupSetBits(scan_evt, SCAN_DONE_BIT);
    }
}


static void wifi_event_roc_done_handler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data)
{
    if(event_base != WIFI_EVENT) return;
    if (event_id == WIFI_EVENT_ROC_DONE) 
    {
        if(roc_evt) xEventGroupSetBits(roc_evt, ROC_DONE_BIT);
    }
}


IRAM_ATTR static void promiscuous_callback(void *buf, wifi_promiscuous_pkt_type_t type)
{
    const wifi_promiscuous_pkt_t *packet = (wifi_promiscuous_pkt_t *)buf;
    uint16_t len = packet->rx_ctrl.sig_len;

    if (packet_queue == NULL) {
        return; // Queue not initialized
    }

    if (len == 0 || len > PACKET_MAX_PAYLOAD_LEN) {
        return;
    }

    if(packet->rx_ctrl.channel != filter_channel && filter_channel != 0) {
        return;
    }

    if (filter_bssid_enabled) 
    {
        bool match = false;
        const uint8_t *payload = packet->payload;
        // Controllo Addr1 (Destinazione) - Presente se len >= 10
        if (len >= 10 && memcmp(payload + 4, filter_bssid, 6) == 0) match = true;
        // Controllo Addr2 (Sorgente) - Presente se len >= 16
        else if (len >= 16 && memcmp(payload + 10, filter_bssid, 6) == 0) match = true;
        // Controllo Addr3 (BSSID/Filtering) - Presente se len >= 22
        else if (len >= 22 && memcmp(payload + 16, filter_bssid, 6) == 0) match = true;

        if (!match) {
            return;
        }
    }

    callback_sniffer_pkt.length = packet->rx_ctrl.sig_len;
    callback_sniffer_pkt.rssi = packet->rx_ctrl.rssi;
    callback_sniffer_pkt.channel = packet->rx_ctrl.channel;
    memcpy(callback_sniffer_pkt.payload, packet->payload, callback_sniffer_pkt.length);

    if( xQueueSend(packet_queue, &callback_sniffer_pkt, 0) != pdTRUE ) {
        return;
    }
}


static void wifi_sniffer_capture_probes(struct libwifi_frame *frame, sniffer_packet_t *sniffer_pkt)
{
    if(frame == NULL || sniffer_pkt == NULL) return;

    if (frame->frame_control.type != TYPE_MANAGEMENT && frame->frame_control.subtype != SUBTYPE_PROBE_REQ) return;

    struct libwifi_sta probe_req_info = {0};
    if (libwifi_parse_probe_req(&probe_req_info, frame) == 0)
    {
        if(strlen(probe_req_info.ssid) == 0) {
            goto cleanup;
        }

        if (xSemaphoreTake(probes_semaphore, pdMS_TO_TICKS(10)) == pdTRUE) 
        {
            const uint8_t *src_mac = (uint8_t *)frame->header.mgmt_ordered.addr2;
            /* Check if this is a new probe request */
            for (int i = 0; i < captured_probes.num_probes; i++) {
                if (memcmp(captured_probes.probes[i].mac, src_mac, 6) == 0 && strcmp(captured_probes.probes[i].ssid, probe_req_info.ssid) == 0) {
                    captured_probes.probes[i].rssi = sniffer_pkt->rssi;
                    captured_probes.probes[i].channel = sniffer_pkt->channel;
                    xSemaphoreGive(probes_semaphore);
                    goto cleanup;
                }
            }
            /* New Probe Request */
            if (captured_probes.num_probes < MAX_PROBE_REQ) {
                memcpy(captured_probes.probes[captured_probes.num_probes].mac, src_mac, 6);
                strncpy(captured_probes.probes[captured_probes.num_probes].ssid, probe_req_info.ssid, 32);
                captured_probes.probes[captured_probes.num_probes].rssi = sniffer_pkt->rssi;
                captured_probes.probes[captured_probes.num_probes].channel = sniffer_pkt->channel;
                captured_probes.num_probes++;
                ESP_LOGI(TAG, "New Probe: %s from %02x:%02x...", probe_req_info.ssid, src_mac[0], src_mac[1]);
            }
            xSemaphoreGive(probes_semaphore);
        }
    cleanup:
        libwifi_free_sta(&probe_req_info);
    }
}


static void wifi_sniffer_capture_clients(struct libwifi_frame *frame, sniffer_packet_t *sniffer_pkt)
{
    if(frame == NULL || sniffer_pkt == NULL) return;

    if (frame->frame_control.type != TYPE_DATA) return;

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


static void wifi_sniffer_capture_handshakes(struct libwifi_frame *frame, sniffer_packet_t *sniffer_pkt)
{
    if (frame == NULL || sniffer_pkt == NULL) return;

    if (frame->frame_control.type != TYPE_DATA) return;

    /* Check if it is a valid WPA Handshake frame */
    if (!libwifi_check_wpa_handshake(frame)) return;

    struct libwifi_wpa_auth_data wpa_data = {0};
    if (libwifi_get_wpa_data(frame, &wpa_data) != 0) return;

    /* Extract MAC addresses */
    // In Data frames: Addr1=Dest, Addr2=Src, Addr3=BSSID
    const uint8_t *dest_mac = (uint8_t *)&frame->header.data.addr1;
    const uint8_t *src_mac = (uint8_t *)&frame->header.data.addr2;
    const uint8_t *bssid = (uint8_t *)&frame->header.data.addr3;
    
    int msg_type = libwifi_check_wpa_message(frame);
    int64_t current_time = esp_timer_get_time(); // Time in microseconds

    if (xSemaphoreTake(handshake_semaphore, pdMS_TO_TICKS(10)) == pdTRUE) 
    {
        /* --- HANDLE M1 (AP -> Station) --- */
        if (msg_type == HANDSHAKE_M1)
        {
            /* Search for existing entry for this BSSID + STA pair */
            handshake_info_t *entry = NULL;
            for (int i = 0; i < captured_handshakes.count; i++) {
                if (memcmp(captured_handshakes.handshake[i].bssid, bssid, 6) == 0 &&
                    memcmp(captured_handshakes.handshake[i].mac_sta, dest_mac, 6) == 0) {
                    entry = &captured_handshakes.handshake[i];
                    break;
                }
            }

            /* If not found, create a new entry */
            if (entry == NULL && captured_handshakes.count < MAX_HANDSHAKE_NUM) {
                entry = &captured_handshakes.handshake[captured_handshakes.count];
                memset(entry, 0, sizeof(handshake_info_t));
                memcpy(entry->bssid, bssid, 6);
                memcpy(entry->mac_sta, dest_mac, 6);
                captured_handshakes.count++;
            }

            if (entry != NULL) {
                /* Store ANonce and Key Version */
                memcpy(entry->anonce, wpa_data.key_info.nonce, 32);
                entry->key_decriptor_version = wpa_data.key_info.information & 0x0003;
                
                /* CRITICAL: Update State for Validation */
                /* We overwrite previous data because a new M1 means a new session started */
                entry->last_m1_timestamp = current_time;
                entry->replay_counter = wpa_data.key_info.replay_counter;
                
                /* Capture PMKID if present in M1 (Robust Security Network IE) */
                if (!entry->pmkid_captured && wpa_data.key_info.key_data_length >= 20) {
                    struct libwifi_tag_iterator iterator = {0};
                    if (libwifi_tag_iterator_init(&iterator, wpa_data.key_info.key_data, wpa_data.key_info.key_data_length) == 0) {
                        const uint8_t *tag_data = iterator.tag_data;
                        /* Check RSN OUI (00:0F:AC) and Type (04) */
                        if (tag_data[0] == 0x00 && tag_data[1] == 0x0F && tag_data[2] == 0xAC && tag_data[3] == 0x04) {
                            memcpy(entry->pmkid, tag_data + 4, 16);
                            entry->pmkid_captured = true;
                            ESP_LOGI(TAG, "PMKID Captured: %02X... (Client: %02X...)", bssid[0], dest_mac[0]);
                            ws_log(TAG, "PMKID Captured: %02X... (Client: %02X...)", bssid[0], dest_mac[0]);
                        }
                    }
                }
            }
        }
        /* --- HANDLE M2 (Station -> AP) --- */
        else if (msg_type == HANDSHAKE_M2)
        {
            /* Search for the entry created by M1 */
            handshake_info_t *entry = NULL;
            for (int i = 0; i < captured_handshakes.count; i++) {
                /* Note: In M2, src_mac is the Station */
                if (memcmp(captured_handshakes.handshake[i].bssid, bssid, 6) == 0 &&
                    memcmp(captured_handshakes.handshake[i].mac_sta, src_mac, 6) == 0) {
                    entry = &captured_handshakes.handshake[i];
                    break;
                }
            }

            if (entry != NULL) 
            {
                /* VALIDATION 1: Check Replay Counter */
                /* The M2 counter MUST match the M1 counter. If not, it belongs to a different session. */
                if (entry->replay_counter != wpa_data.key_info.replay_counter) {
                    ESP_LOGD(TAG, "M2 discarded: Replay Counter mismatch (M1:%llu != M2:%llu)", 
                            entry->replay_counter, wpa_data.key_info.replay_counter);
                    // FIX: Non usare goto per uscire dal blocco semaforo senza rilasciarlo
                }
                /* VALIDATION 2: Check Timestamp (Timeout) */
                /* If M1 is too old (e.g., > 2 seconds), discard M2 to avoid stale data */
                else if ((current_time - entry->last_m1_timestamp) > HANDSHAKE_TIMEOUT_US) {
                    ESP_LOGD(TAG, "M2 discarded: M1 timeout");
                }
                else {
                    /* Validation Passed: Store SNonce and MIC */
                    memcpy(entry->snonce, wpa_data.key_info.nonce, 32);
                    memcpy(entry->mic, wpa_data.key_info.mic, 16);

                    /* Extract Raw EAPOL frame (required for cracking tools like aircrack-ng) */
                    uint16_t raw_len = 0;
                    uint8_t *raw_ptr = find_eapol_frame(sniffer_pkt->payload, sniffer_pkt->length, &raw_len);
                    
                    if (raw_ptr && raw_len <= sizeof(entry->eapol)) {
                        memcpy(entry->eapol, raw_ptr, raw_len);
                        entry->eapol_len = raw_len;
                        
                        /* Zero out the MIC in the raw frame if needed (standard practice) */
                        if (entry->eapol_len > 81 + 16) {
                            memset(entry->eapol + 81, 0, 16);
                        }

                        if (!entry->handshake_captured) {
                            entry->handshake_captured = true;
                            ESP_LOGI(TAG, "Handshake (M1+M2) Captured! AP: %02X... Client: %02X...", bssid[0], src_mac[0]);
                            ws_log(TAG, "Handshake (M1+M2) Captured! AP: %02X... Client: %02X...", bssid[0], src_mac[0]);
                        }
                    }
                }
            } 
        } // if M1 or M2
        xSemaphoreGive(handshake_semaphore); // FIX: Release correct semaphore!
    } // Semaphore

    libwifi_free_wpa_data(&wpa_data);
}


static void wifi_sniffer_packet_analyzer_handler(struct libwifi_frame *frame, sniffer_packet_t *sniffer_pkt)
{
    if (frame == NULL || sniffer_pkt == NULL) return;

    // Rate Limiting
    static int64_t last_pkt_time = 0;
    if (esp_timer_get_time() - last_pkt_time < 5000) return; 

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
    char type_str[10] = "UNK";
    char subtype_str[32] = "Unk";
    char info[128] = "";
    char sec[32] = "UNK";

    if (type == TYPE_MANAGEMENT) {
        strcpy(type_str, "MGMT");
        switch(subtype) {
            case SUBTYPE_ASSOC_REQ: strcpy(subtype_str, "ASSOC_REQ"); break;
            case SUBTYPE_ASSOC_RESP: strcpy(subtype_str, "ASSOC_RESP"); break;
            case SUBTYPE_REASSOC_REQ: strcpy(subtype_str, "REASSOC_REQ"); break;
            case SUBTYPE_REASSOC_RESP: strcpy(subtype_str, "REASSOC_RESP"); break;
            case SUBTYPE_PROBE_REQ: {
                strcpy(subtype_str, "PROBE_REQ");
                struct libwifi_sta sta = {0};
                if (libwifi_parse_probe_req(&sta, frame) == 0) {
                    snprintf(info, sizeof(info),
                            "SSID:%s%s | Ch:%u",
                            sta.ssid,
                            sta.broadcast_ssid ? " (hidden)" : "",
                            sta.channel);
                    libwifi_free_sta(&sta);
                }
            } break;

            case SUBTYPE_PROBE_RESP: {
                strcpy(subtype_str, "PROBE_RESP");
                struct libwifi_bss bss = {0};
                if (libwifi_parse_probe_resp(&bss, frame) == 0) {
                    libwifi_get_security_type_s(&bss, sec, sizeof(sec));
                    snprintf(info, sizeof(info),
                            "SSID:%s%s | Ch:%u | Sec:%s | WPS:%s",
                            bss.ssid,
                            bss.hidden ? " (hidden)" : "",
                            bss.channel,
                            sec,
                            bss.wps ? "yes" : "no");
                    libwifi_free_bss(&bss);
                }
            } break;

            case SUBTYPE_TIME_ADV: strcpy(subtype_str, "TIME_ADV"); break;
            case SUBTYPE_BEACON: {
                strcpy(subtype_str, "BEACON");
                struct libwifi_bss bss = {0};
                if (libwifi_parse_beacon(&bss, frame) == 0) {
                    libwifi_get_security_type_s(&bss, sec, sizeof(sec));
                    snprintf(info, sizeof(info),
                            "SSID:%s%s | Ch:%u | Sec:%s | WPS:%s",
                            bss.ssid,
                            bss.hidden ? " (hidden)" : "",
                            bss.channel,
                            sec,
                            bss.wps ? "yes" : "no");
                    libwifi_free_bss(&bss);
                }
            } break;

            case SUBTYPE_ATIM: strcpy(subtype_str, "ATIM"); break;
            case SUBTYPE_DISASSOC: {
                strcpy(subtype_str, "DISASSOC");
                struct libwifi_parsed_disassoc dis = {0};
                if (libwifi_parse_disassoc(&dis, frame) == 0) {
                    snprintf(info, sizeof(info), "Reason:%u (0x%04X)", dis.fixed_parameters.reason_code, dis.fixed_parameters.reason_code);
                }
            } break;

            case SUBTYPE_AUTH: strcpy(subtype_str, "AUTH"); break;
            case SUBTYPE_DEAUTH: {
                strcpy(subtype_str, "DEAUTH");
                struct libwifi_parsed_deauth de = {0};
                if (libwifi_parse_deauth(&de, frame) == 0) {
                    snprintf(info, sizeof(info), "Reason:%u", de.fixed_parameters.reason_code);
                    libwifi_free_parsed_deauth(&de);
                }
            } break;

            case SUBTYPE_ACTION: {
                strcpy(subtype_str, "ACTION");
                size_t body_len = frame->len - frame->header_len;
                if (body_len >= 2) {
                    uint8_t category = frame->body[0];
                    uint8_t action_code = frame->body[1];
                    snprintf(info, sizeof(info), "Category:%u | Act:%u", category, action_code);
                } else {
                    snprintf(info, sizeof(info), "Malformed ACTION");
                }
            } break;

            case SUBTYPE_ACTION_NOACK: strcpy(subtype_str, "ACTION_NOACK"); break;
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
        struct libwifi_wpa_auth_data wpa_data = {0};
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
    sniffer_packet_t parsing_sniffer_pkt = {0};

    while (1)
    {
        if (xQueueReceive(packet_queue, &parsing_sniffer_pkt, portMAX_DELAY) == pdTRUE)
        {
            struct libwifi_frame frame = {0};
            int ret = libwifi_get_wifi_frame(&frame, (uint8_t *)parsing_sniffer_pkt.payload, parsing_sniffer_pkt.length, false);

            /* Failed to parse the Wi-Fi frame */
            if (ret != 0)
            {
                #ifdef DEBUG
                ESP_LOGE(TAG, "Failed to parse wifi frame.");
                #endif
                goto cleanup;
            }

            if(live_packet_analyzer == true) {
                wifi_sniffer_packet_analyzer_handler(&frame, &parsing_sniffer_pkt);
            }

            if (frame.frame_control.type == TYPE_MANAGEMENT) {
                if (frame.frame_control.subtype == SUBTYPE_PROBE_REQ) {
                    wifi_sniffer_capture_probes(&frame, &parsing_sniffer_pkt);
                }
            }
            else if (frame.frame_control.type == TYPE_DATA) {
                wifi_sniffer_capture_handshakes(&frame, &parsing_sniffer_pkt);
                wifi_sniffer_capture_clients(&frame, &parsing_sniffer_pkt);
            }

        cleanup:
            /* Cleanup allocated resources */
            libwifi_free_wifi_frame(&frame);
        }
    }
}


esp_err_t wifi_start_sniffing(void)
{
    bool en = false;
    ESP_ERROR_CHECK(esp_wifi_get_promiscuous(&en));
    /* Start wifi promiscuos mode */
    if (en == true)
    {
        ESP_LOGW(TAG, "Promiscuous mode already enabled");
        return ESP_ERR_INVALID_STATE;
    }

    /* Init semaphore */
    if (clients_semaphore == NULL) clients_semaphore = xSemaphoreCreateMutex();
    if (aps_semaphore == NULL) aps_semaphore = xSemaphoreCreateMutex();
    if (handshake_semaphore == NULL) handshake_semaphore = xSemaphoreCreateMutex();
    if (probes_semaphore == NULL) probes_semaphore = xSemaphoreCreateMutex();

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

    /* Reset client count */
    memset(&clients, 0, sizeof(client_list_t));
    memset(&captured_handshakes, 0, sizeof(handshake_info_list_t));
    memset(&captured_probes, 0, sizeof(probe_request_list_t));

    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_DATA | WIFI_PROMIS_FILTER_MASK_MGMT};
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filter));
    filter.filter_mask = 0;
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_ctrl_filter(&filter));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(promiscuous_callback));

    return ESP_OK;
}


esp_err_t wifi_stop_sniffing(void)
{
    bool en = false;
    ESP_ERROR_CHECK(esp_wifi_get_promiscuous(&en));

    /* Clear filters and channel hopping */
    wifi_sniffer_start_packet_analyzer(false);
    wifi_sniffer_set_bssid_filter(NULL);
    wifi_sniffer_set_fine_filter(0, 0, 0);
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
    if (clients_semaphore != NULL) { vSemaphoreDelete(clients_semaphore); clients_semaphore = NULL; }
    if (aps_semaphore != NULL) { vSemaphoreDelete(aps_semaphore); aps_semaphore = NULL; }
    if (handshake_semaphore != NULL) { vSemaphoreDelete(handshake_semaphore); handshake_semaphore = NULL; }
    if (probes_semaphore != NULL) { vSemaphoreDelete(probes_semaphore); probes_semaphore = NULL; }

    filter_channel = 0;
    return ESP_OK;
}


void wifi_sniffer_set_fine_filter(int type, uint32_t subtype, uint8_t channel) 
{
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


void wifi_sniffer_set_bssid_filter(uint8_t *bssid) 
{
    if(bssid) {
        memcpy(filter_bssid, bssid, 6);
        filter_bssid_enabled = true;
    } else {
        filter_bssid_enabled = false;
    }
}


esp_err_t wifi_sniffer_start_channel_hopping(uint8_t channel)
{
    if(roc_evt == NULL) {
        roc_evt = xEventGroupCreate();
    }
    if(scan_evt == NULL) {
        scan_evt = xEventGroupCreate();
    }

    if(roc_evt == NULL) {
        ESP_LOGE(TAG, "Failed to create roc event group.");
        return ESP_FAIL;
    }
    if(scan_evt == NULL) {
        ESP_LOGE(TAG, "Failed to create scan done event group.");
        return ESP_FAIL;
    }

    if(roc_done_event_instance == NULL) {
        ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, WIFI_EVENT_ROC_DONE, &wifi_event_roc_done_handler, NULL, &roc_done_event_instance));
    }
    if(scan_done_event_instance == NULL) {
        ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, WIFI_EVENT_SCAN_DONE, &wifi_event_scan_done_handler, NULL, &scan_done_event_instance));
    }

    if (channel_hopping_task_handle == NULL)
    {
        xTaskCreate(wifi_sniffer_channel_hopping_task, "channel_hopping_task", 4096, (void*)(uintptr_t)channel, CHANNEL_HOPPING_TASK_PRIO, &channel_hopping_task_handle);
    }
    return ESP_OK;
}


esp_err_t wifi_sniffer_stop_channel_hopping(void)
{
    esp_wifi_scan_stop();
    vTaskDelay(pdMS_TO_TICKS(10));

    if(roc_done_event_instance != NULL) {
        ESP_ERROR_CHECK(esp_event_handler_instance_unregister(WIFI_EVENT, WIFI_EVENT_ROC_DONE, roc_done_event_instance));
        roc_done_event_instance = NULL;
    }
    if(scan_done_event_instance != NULL) {
        ESP_ERROR_CHECK(esp_event_handler_instance_unregister(WIFI_EVENT, WIFI_EVENT_SCAN_DONE, scan_done_event_instance));
        scan_done_event_instance = NULL;
    }
    vTaskDelay(pdMS_TO_TICKS(10));

    if (channel_hopping_task_handle != NULL)
    {
        vTaskDelete(channel_hopping_task_handle);
        channel_hopping_task_handle = NULL;
    }
    vTaskDelay(pdMS_TO_TICKS(10));

    if(roc_evt != NULL) {
        vEventGroupDelete(roc_evt);
        roc_evt = NULL;
    }
    if(scan_evt != NULL) {
        vEventGroupDelete(scan_evt);
        scan_evt = NULL;
    }
    return ESP_OK;
}


void wifi_sniffer_start_packet_analyzer(bool start)
{
    live_packet_analyzer = start;
}

/* ################ GETTER FUNCTIONS ########################## */
esp_err_t wifi_sniffer_get_probes(probe_request_list_t *out)
{
    if(out == NULL) return ESP_ERR_INVALID_ARG;

    if (probes_semaphore == NULL) {
        probes_semaphore = xSemaphoreCreateMutex();
    }

    if (xSemaphoreTake(probes_semaphore, pdMS_TO_TICKS(100)) == pdTRUE) 
    {
        memcpy(out, &captured_probes, sizeof(probe_request_list_t));
        xSemaphoreGive(probes_semaphore);
        return ESP_OK;
    }
    return ESP_FAIL;
}


esp_err_t wifi_sniffer_get_handshake_for_target(const uint8_t *bssid, const uint8_t *client_mac, handshake_info_t *out)
{
    if (bssid == NULL || out == NULL) return ESP_ERR_INVALID_ARG;

    if (handshake_semaphore == NULL) {
        handshake_semaphore = xSemaphoreCreateMutex();
    }

    if (xSemaphoreTake(handshake_semaphore, pdMS_TO_TICKS(100)) == pdTRUE) 
    {
        for (int i = 0; i < captured_handshakes.count; i++) {
            /* Check BSSID */
            if (memcmp(captured_handshakes.handshake[i].bssid, bssid, 6) == 0) {
                
                /* Se client_mac è specificato, controllalo. Altrimenti prendi il primo handshake valido per quell'AP */
                if (client_mac == NULL || memcmp(captured_handshakes.handshake[i].mac_sta, client_mac, 6) == 0) {
                    
                    /* Check valid data */
                    if (captured_handshakes.handshake[i].handshake_captured || 
                        captured_handshakes.handshake[i].pmkid_captured) {
                        memcpy(out, &captured_handshakes.handshake[i], sizeof(handshake_info_t));
                        xSemaphoreGive(handshake_semaphore);
                        return ESP_OK;
                    }
                }
            }
        }
        xSemaphoreGive(handshake_semaphore);
    }
    
    return ESP_FAIL;
}


int wifi_sniffer_get_handshake_status_for_target(const uint8_t *bssid)
{
    if (bssid == NULL) return 0;

    for (int i = 0; i < captured_handshakes.count; i++) {
        /* Check BSSID */
        if (memcmp(captured_handshakes.handshake[i].bssid, bssid, 6) == 0) {
            if (captured_handshakes.handshake[i].handshake_captured ) {
                return 1;
            }
            if (captured_handshakes.handshake[i].pmkid_captured) {
                return 2;
            }
        }
    }
    return 0;
}


esp_err_t wifi_sniffer_get_clients(client_list_t *out)
{
    if(out == NULL) return ESP_ERR_INVALID_ARG;

    if (clients_semaphore == NULL) {
        clients_semaphore = xSemaphoreCreateMutex();
    }

    if (xSemaphoreTake(clients_semaphore, pdMS_TO_TICKS(100)) == pdTRUE) 
    {
        memcpy(out, &clients, sizeof(client_list_t));
        xSemaphoreGive(clients_semaphore);
        return ESP_OK;
    }
    return ESP_FAIL;
}


uint8_t wifi_sniffer_get_clients_count(void)
{
    return clients.count;
}


esp_err_t wifi_sniffer_get_aps(aps_info_t *out)
{
    if(out == NULL) return ESP_ERR_INVALID_ARG;

    if (aps_semaphore == NULL) {
        aps_semaphore = xSemaphoreCreateMutex();
    }

    if (xSemaphoreTake(aps_semaphore, pdMS_TO_TICKS(100)) == pdTRUE) 
    {
        memcpy(out, &detected_aps, sizeof(aps_info_t));
        xSemaphoreGive(aps_semaphore);
        return ESP_OK;
    }
    return ESP_FAIL;
}


uint8_t wifi_sniffer_get_aps_count(void)
{
    return detected_aps.count;
}


esp_err_t wifi_sniffer_scan_fill_aps(void) 
{
    if (aps_semaphore == NULL) {
        aps_semaphore = xSemaphoreCreateMutex();
    }

    wifi_scan_config_t scan_config = {
        .ssid = NULL,
        .bssid = NULL,
        .channel = 0,
        .show_hidden = false,
        .scan_type = WIFI_SCAN_TYPE_ACTIVE,
        .scan_time.active.min = 0,
        .scan_time.active.max = 150,
        .home_chan_dwell_time = 150,
    };
    
    if(esp_wifi_scan_start(&scan_config, true) != ESP_OK ) return ESP_FAIL;
    uint16_t ap_count = 0;
    esp_wifi_scan_get_ap_num(&ap_count);

    if (ap_count > 0) 
    {
        wifi_ap_record_t *ap_records = (wifi_ap_record_t *)calloc(ap_count, sizeof(wifi_ap_record_t));
        if (ap_records) 
        {
            if (esp_wifi_scan_get_ap_records(&ap_count, ap_records) == ESP_OK) 
            {
                if (xSemaphoreTake(aps_semaphore, pdMS_TO_TICKS(100)) == pdTRUE) 
                {
                    for (int i = 0; i < ap_count; i++) 
                    {
                        if (ap_records[i].rssi < -95) continue; 
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
    return ESP_OK;
}
/* ########################################################### */

static void wifi_sniffer_channel_hopping_task(void *param)
{
    uint8_t target_channel = (uint8_t)(uintptr_t)param;
    uint8_t current_channel = 1;
    const uint32_t ROC_DURATION_MS = 10;
    const uint32_t AP_REST_TIME_MS = 80;

    while (1)
    {
        if (roc_evt != NULL) {
            xEventGroupClearBits(roc_evt, ROC_DONE_BIT);
        }

        uint8_t channel_to_scan = 0;
        if (target_channel != 0) {
            channel_to_scan = target_channel;
        } else {
            channel_to_scan = current_channel;
        }

        wifi_roc_req_t req = {
            .ifx = WIFI_IF_STA,
            .type = WIFI_ROC_REQ,
            .channel = channel_to_scan,
            .sec_channel = WIFI_SECOND_CHAN_NONE,
            .wait_time_ms = ROC_DURATION_MS, 
            .rx_cb = NULL,
            .done_cb = NULL
        };
        esp_err_t err = esp_wifi_remain_on_channel(&req);
        if (err == ESP_OK) {
            if (roc_evt != NULL) {
                xEventGroupWaitBits(roc_evt, ROC_DONE_BIT, pdTRUE, pdFALSE, pdMS_TO_TICKS(ROC_DURATION_MS + 50));
            }
        } else {
             ESP_LOGW(TAG, "ROC request failed: %s", esp_err_to_name(err));
        }

        vTaskDelay(pdMS_TO_TICKS(AP_REST_TIME_MS));
        if (target_channel == 0) {
            current_channel++;
            if (current_channel > 13) current_channel = 1;
        }
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