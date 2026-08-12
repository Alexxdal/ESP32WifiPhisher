#include <esp_log.h>
#include "scanner.h"
#include "esp_netif.h"
#include "esp_netif_net_stack.h"
#include "lwip/etharp.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "cJSON.h"
#include "networking.h"
#include "dns.h"

static const char *TAG = "SCANNER";

char* subnet_scan(void)
{
    esp_netif_ip_info_t *sta_ip = networking_get_ip_info();
    esp_netif_t *esp_netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (esp_netif == NULL || sta_ip == NULL) {
        ESP_LOGE(TAG, "Wifi Interface not ready.");
        return NULL;
    }
    struct netif *lwip_netif = (struct netif *)esp_netif_get_netif_impl(esp_netif);
    uint32_t ip_host = lwip_ntohl(sta_ip->ip.addr);
    uint32_t mask_host = lwip_ntohl(sta_ip->netmask.addr);
    uint32_t network_host = ip_host & mask_host;
    uint32_t broadcast_host = network_host | ~mask_host;

    ip4_addr_t local_dns_server = {0};
    bool have_dns_server = false;
    esp_netif_dns_info_t dns_info;
    if (esp_netif_get_dns_info(esp_netif, ESP_NETIF_DNS_MAIN, &dns_info) == ESP_OK &&
        dns_info.ip.type == ESP_IPADDR_TYPE_V4 &&
        dns_info.ip.u_addr.ip4.addr != 0) {
        local_dns_server.addr = dns_info.ip.u_addr.ip4.addr;
        have_dns_server = true;
    } else {
        ESP_LOGW(TAG, "No local DNS hostname not resolved");
    }

    cJSON *result_array = cJSON_CreateArray();
    if (result_array == NULL) return NULL;

    const uint32_t BATCH_SIZE = 4;
    const uint32_t WAIT_MS = 150;
    const uint32_t NUM_PASSES = 2;

    if (broadcast_host <= network_host + 1) {
        char *empty = cJSON_PrintUnformatted(result_array);
        cJSON_Delete(result_array);
        return empty;
    }

    uint32_t host_count = broadcast_host - network_host - 1;
    uint8_t *found = calloc((host_count / 8) + 1, 1);
    if (found == NULL) {
        ESP_LOGE(TAG, "Failed to allocate found-bitset");
        cJSON_Delete(result_array);
        return NULL;
    }

    for (uint32_t pass = 0; pass < NUM_PASSES; pass++) {
        for (uint32_t i = network_host + 1; i < broadcast_host; i += BATCH_SIZE) {
            for (uint32_t j = 0; j < BATCH_SIZE && (i + j) < broadcast_host; j++) {
                uint32_t idx = (i + j) - (network_host + 1);
                if (found[idx / 8] & (1 << (idx % 8))) {
                    continue;
                }
                ip4_addr_t ipaddr;
                ipaddr.addr = lwip_htonl(i + j);
                etharp_request(lwip_netif, &ipaddr);
            }
            vTaskDelay(pdMS_TO_TICKS(WAIT_MS));

            for (uint32_t j = 0; j < BATCH_SIZE && (i + j) < broadcast_host; j++) {
                uint32_t idx = (i + j) - (network_host + 1);
                if (found[idx / 8] & (1 << (idx % 8))) {
                    continue;
                }
                ip4_addr_t ipaddr;
                ipaddr.addr = lwip_htonl(i + j);
                struct eth_addr *eth_ret = NULL;
                const ip4_addr_t *ip_ret = NULL;
                ssize_t entry_found = etharp_find_addr(lwip_netif, &ipaddr, &eth_ret, &ip_ret);

                if (entry_found >= 0 && eth_ret != NULL) {
                    found[idx / 8] |= (1 << (idx % 8));

                    cJSON *result_obj = cJSON_CreateObject();
                    cJSON_AddStringToObject(result_obj, "ip", ip4addr_ntoa(&ipaddr));
                    char mac_str[18];
                    snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                            eth_ret->addr[0], eth_ret->addr[1], eth_ret->addr[2],
                            eth_ret->addr[3], eth_ret->addr[4], eth_ret->addr[5]);
                    cJSON_AddStringToObject(result_obj, "mac", mac_str);

                    char hostname[64] = {0};
                    if (have_dns_server) {
                        dns_reverse_lookup_ex(ipaddr, local_dns_server, hostname, sizeof(hostname), 800, 2);
                    } else {
                        snprintf(hostname, sizeof(hostname), "N/A");
                    }

                    cJSON_AddStringToObject(result_obj, "hostname", hostname);
                    cJSON_AddItemToArray(result_array, result_obj);
                }
            }
        }
    }

    free(found);

    char *results = cJSON_PrintUnformatted(result_array);
    cJSON_Delete(result_array);

    return results;
}