#include <string.h>
#include "esp_log.h"
#include "arpa/inet.h"
#include "utils.h"

bool isMacBroadcast(const uint8_t *mac)
{
    uint8_t broadcast[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    return memcmp(mac, broadcast, 6) == 0;
}


bool isMacZero(uint8_t *mac)
{
    uint8_t zero_mac[6] = {0};
    return memcmp(mac, zero_mac, 6) == 0;
}


bool isMacEqual(const uint8_t *mac1, const uint8_t *mac2)
{
    return memcmp(mac1, mac2, 6) == 0;
}


void print_packet(uint8_t *data, size_t len)
{
    printf("\nPACKET DATA: ############\n");
    for(size_t i = 0; i < len; i++ )
    {
        printf("%02X ", data[i]);
    }
    printf("\n####################\n");
}


void print_buffer(uint8_t *buffer, size_t len)
{
    for(size_t i = 0; i < len; i++ )
    {
        printf("%02X ", buffer[i]);
    }
}


void print_handshake(handshake_info_t *handshake)
{
    printf("\nHANDSHAKE DATA: ############\n");
    printf("Station: ");
    print_buffer(handshake->mac_sta, sizeof(handshake->mac_sta));
    printf("\nANonce: ");
    print_buffer(handshake->anonce, sizeof(handshake->anonce));
    printf("\nSNonce: ");
    print_buffer(handshake->snonce, sizeof(handshake->snonce));
    printf("\nMIC: ");
    print_buffer(handshake->mic, sizeof(handshake->mic));
    printf("\nEAPOL: ");
    print_buffer(handshake->eapol, handshake->eapol_len);
    printf("\nKey Descriptor Version: %d", handshake->key_decriptor_version);
    printf("\n#####################\n");
}


uint8_t getNextChannel(uint8_t current_channel)
{
    if( current_channel >= 14 )
    {
        return 1;
    }
    else
    {
        return current_channel + 1;
    }
}


const char *authmode_to_str(wifi_auth_mode_t m)
{
    switch (m) {
        case WIFI_AUTH_OPEN:                        return "OPEN";
        case WIFI_AUTH_WEP:                         return "WEP";
        case WIFI_AUTH_WPA_PSK:                     return "WPA_PSK";
        case WIFI_AUTH_WPA2_PSK:                    return "WPA2_PSK";
        case WIFI_AUTH_WPA_WPA2_PSK:                return "WPA_WPA2_PSK";
        case WIFI_AUTH_WPA2_ENTERPRISE:             return "WPA2_ENTERPRISE"; // Include anche WIFI_AUTH_ENTERPRISE
        case WIFI_AUTH_WPA3_PSK:                    return "WPA3_PSK";
        case WIFI_AUTH_WPA2_WPA3_PSK:               return "WPA2_WPA3_PSK";
        case WIFI_AUTH_WAPI_PSK:                    return "WAPI_PSK";
        case WIFI_AUTH_OWE:                         return "OWE";
        case WIFI_AUTH_WPA3_ENT_192:                return "WPA3_ENT_SUITE_B_192_BIT";
        case WIFI_AUTH_WPA3_EXT_PSK:                return "WPA3_EXT_PSK";
        case WIFI_AUTH_WPA3_EXT_PSK_MIXED_MODE:     return "WPA3_EXT_PSK_MIXED_MODE";
        case WIFI_AUTH_DPP:                         return "DPP";
        case WIFI_AUTH_WPA3_ENTERPRISE:             return "WPA3_ENTERPRISE";
        case WIFI_AUTH_WPA2_WPA3_ENTERPRISE:        return "WPA2_WPA3_ENTERPRISE";
        case WIFI_AUTH_WPA_ENTERPRISE:              return "WPA_ENTERPRISE";
        default:                                    return "UNKNOWN";
    }
}


void hex_dump_bytes(const char *tag, const uint8_t *buf, size_t len)
{
    if (!buf || len == 0) return;

    printf("%s (%u bytes)\n", tag, (unsigned)len);

    for (size_t i = 0; i < len; i += 16) {
        printf("%04u: ", (unsigned)i);
        for (size_t j = 0; j < 16 && (i + j) < len; j++) {
            printf("%02X ", buf[i + j]);
        }
        printf(" |");
        for (size_t j = 0; j < 16 && (i + j) < len; j++) {
            uint8_t c = buf[i + j];
            printf("%c", (c >= 32 && c <= 126) ? (char)c : '.');
        }
        printf("|\n");
    }
}