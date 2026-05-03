#include <string.h>
#include "oui_database.h"
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


bool macstr_to_bytes(const char *mac_str, uint8_t *mac_out) 
{
    if (mac_str == NULL || mac_out == NULL || strlen(mac_str) != 17) {
        return false;
    }
    int bytes[6];
    if (sscanf(mac_str, "%x:%x:%x:%x:%x:%x", 
        &bytes[0], &bytes[1], &bytes[2], &bytes[3], &bytes[4], &bytes[5]) != 6) {
        return false;
    }
    for (int i = 0; i < 6; i++) {
        mac_out[i] = (uint8_t)bytes[i];
    }
    return true;
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


const char *wifi_rate_to_str(wifi_phy_rate_t rate)
{
    switch (rate) {
        // 802.11b Rates (Long Preamble)
        case WIFI_PHY_RATE_1M_L:      return "1 Mbps (Long Preamble)";
        case WIFI_PHY_RATE_2M_L:      return "2 Mbps (Long Preamble)";
        case WIFI_PHY_RATE_5M_L:      return "5.5 Mbps (Long Preamble)";
        case WIFI_PHY_RATE_11M_L:     return "11 Mbps (Long Preamble)";
        // 802.11b Rates (Short Preamble)
        case WIFI_PHY_RATE_2M_S:      return "2 Mbps (Short Preamble)";
        case WIFI_PHY_RATE_5M_S:      return "5.5 Mbps (Short Preamble)";
        case WIFI_PHY_RATE_11M_S:     return "11 Mbps (Short Preamble)";
        // 802.11g Rates
        case WIFI_PHY_RATE_48M:       return "48 Mbps";
        case WIFI_PHY_RATE_24M:       return "24 Mbps";
        case WIFI_PHY_RATE_12M:       return "12 Mbps";
        case WIFI_PHY_RATE_6M:        return "6 Mbps";
        case WIFI_PHY_RATE_54M:       return "54 Mbps";
        case WIFI_PHY_RATE_36M:       return "36 Mbps";
        case WIFI_PHY_RATE_18M:       return "18 Mbps";
        case WIFI_PHY_RATE_9M:        return "9 Mbps";
        // 802.11n/ac/ax MCS Rates (Long Guard Interval)
        case WIFI_PHY_RATE_MCS0_LGI:  return "MCS0 (LGI)";
        case WIFI_PHY_RATE_MCS1_LGI:  return "MCS1 (LGI)";
        case WIFI_PHY_RATE_MCS2_LGI:  return "MCS2 (LGI)";
        case WIFI_PHY_RATE_MCS3_LGI:  return "MCS3 (LGI)";
        case WIFI_PHY_RATE_MCS4_LGI:  return "MCS4 (LGI)";
        case WIFI_PHY_RATE_MCS5_LGI:  return "MCS5 (LGI)";
        case WIFI_PHY_RATE_MCS6_LGI:  return "MCS6 (LGI)";
        case WIFI_PHY_RATE_MCS7_LGI:  return "MCS7 (LGI)";
#if CONFIG_SOC_WIFI_HE_SUPPORT || !CONFIG_SOC_WIFI_SUPPORTED
        case WIFI_PHY_RATE_MCS8_LGI:  return "MCS8 (LGI)";
        case WIFI_PHY_RATE_MCS9_LGI:  return "MCS9 (LGI)";
#endif
        // 802.11n/ac/ax MCS Rates (Short Guard Interval)
        case WIFI_PHY_RATE_MCS0_SGI:  return "MCS0 (SGI)";
        case WIFI_PHY_RATE_MCS1_SGI:  return "MCS1 (SGI)";
        case WIFI_PHY_RATE_MCS2_SGI:  return "MCS2 (SGI)";
        case WIFI_PHY_RATE_MCS3_SGI:  return "MCS3 (SGI)";
        case WIFI_PHY_RATE_MCS4_SGI:  return "MCS4 (SGI)";
        case WIFI_PHY_RATE_MCS5_SGI:  return "MCS5 (SGI)";
        case WIFI_PHY_RATE_MCS6_SGI:  return "MCS6 (SGI)";
        case WIFI_PHY_RATE_MCS7_SGI:  return "MCS7 (SGI)";
        
#if CONFIG_SOC_WIFI_HE_SUPPORT || !CONFIG_SOC_WIFI_SUPPORTED
        case WIFI_PHY_RATE_MCS8_SGI:  return "MCS8 (SGI)";
        case WIFI_PHY_RATE_MCS9_SGI:  return "MCS9 (SGI)";
#endif
        // Proprietary LoRa Rates
        case WIFI_PHY_RATE_LORA_250K: return "LoRa 250 Kbps";
        case WIFI_PHY_RATE_LORA_500K: return "LoRa 500 Kbps";
        
        default:                      return "UNKNOWN_RATE";
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


static int oui_compare(const void *key, const void *element) 
{
    uint32_t target = *(const uint32_t *)key;
    const mac_oui_t *entry = (const mac_oui_t *)element;
    if (target < entry->oui) return -1;
    if (target > entry->oui) return 1;
    return 0;
}


const char* resolve_mac_oui(const uint8_t mac[6]) 
{
    uint32_t target_oui = (mac[0] << 16) | (mac[1] << 8) | mac[2];

    if ((mac[0] & 0x02) == 0x02) {
        return "Randomized MAC"; 
    }
    
    size_t db_size = sizeof(oui_db) / sizeof(oui_db[0]);
    mac_oui_t *result = bsearch(&target_oui, oui_db, db_size, sizeof(mac_oui_t), oui_compare);
    if (result != NULL) {
        return result->vendor;
    }
    return "Unknown Vendor";
}