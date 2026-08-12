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

esp_err_t subnet_scan(void)
{
    esp_netif_ip_info_t *sta_ip = networking_get_ip_info();
    esp_netif_t *esp_netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (esp_netif == NULL || sta_ip == NULL) {
        ESP_LOGE(TAG, "Interfaccia Wi-Fi non pronta.");
        return ESP_FAIL;
    }
    struct netif *lwip_netif = (struct netif *)esp_netif_get_netif_impl(esp_netif);
    uint32_t ip_host = lwip_ntohl(sta_ip->ip.addr);
    uint32_t mask_host = lwip_ntohl(sta_ip->netmask.addr);
    uint32_t network_host = ip_host & mask_host;
    uint32_t broadcast_host = network_host | ~mask_host;
 
    // DNS server actually handed out by the router (DHCP), not a hardcoded
    // public resolver: 8.8.8.8/1.1.1.1 have no PTR records for private LAN
    // addresses, but most home routers register DHCP client hostnames in
    // their own local resolver.
    ip4_addr_t local_dns_server = {0};
    bool have_dns_server = false;
    esp_netif_dns_info_t dns_info;
    if (esp_netif_get_dns_info(esp_netif, ESP_NETIF_DNS_MAIN, &dns_info) == ESP_OK &&
        dns_info.ip.type == ESP_IPADDR_TYPE_V4 &&
        dns_info.ip.u_addr.ip4.addr != 0) {
        local_dns_server.addr = dns_info.ip.u_addr.ip4.addr;
        have_dns_server = true;
    } else {
        ESP_LOGW(TAG, "Nessun DNS locale disponibile, hostname non risolti");
    }
 
    ESP_LOGI(TAG, "Avvio scansione ARP in corso...");
 
    cJSON *result_array = cJSON_CreateArray();
    if (result_array == NULL) return ESP_ERR_NO_MEM;
    const uint32_t BATCH_SIZE = 4;
    const uint32_t WAIT_MS = 150;
 
    for (uint32_t i = network_host + 1; i < broadcast_host; i += BATCH_SIZE) {
        for (uint32_t j = 0; j < BATCH_SIZE && (i + j) < broadcast_host; j++) {
            ip4_addr_t ipaddr;
            ipaddr.addr = lwip_htonl(i + j);
            etharp_request(lwip_netif, &ipaddr);
        }
        vTaskDelay(pdMS_TO_TICKS(WAIT_MS));
 
        for (uint32_t j = 0; j < BATCH_SIZE && (i + j) < broadcast_host; j++) {
            ip4_addr_t ipaddr;
            ipaddr.addr = lwip_htonl(i + j);
            struct eth_addr *eth_ret = NULL;
            const ip4_addr_t *ip_ret = NULL;
            ssize_t found = etharp_find_addr(lwip_netif, &ipaddr, &eth_ret, &ip_ret);
 
            if (found >= 0 && eth_ret != NULL) {
                cJSON *result_obj = cJSON_CreateObject();
                cJSON_AddStringToObject(result_obj, "ip", ip4addr_ntoa(&ipaddr));
                char mac_str[18];
                snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                        eth_ret->addr[0], eth_ret->addr[1], eth_ret->addr[2],
                        eth_ret->addr[3], eth_ret->addr[4], eth_ret->addr[5]);
                cJSON_AddStringToObject(result_obj, "mac", mac_str);
 
                char hostname[64] = {0};
                if (have_dns_server) {
                    // Short budget on purpose: this runs once per host found
                    // during the scan, and a LAN round trip should be near-
                    // instant if the router is going to answer at all — no
                    // need for the 3x10s budget meant for a one-off internet
                    // lookup (dns_reverse_lookup()'s default).
                    dns_reverse_lookup_ex(ipaddr, local_dns_server, hostname, sizeof(hostname), 800, 2);
                } else {
                    snprintf(hostname, sizeof(hostname), "N/A");
                }
 
                cJSON_AddStringToObject(result_obj, "hostname", hostname);
                cJSON_AddItemToArray(result_array, result_obj);
            }
        }
    }
    char *results = cJSON_PrintUnformatted(result_array);
    cJSON_Delete(result_array);
    if (results != NULL) {
        ESP_LOGI(TAG, "Subnet Scan Results: %s", results);
        free(results);
    } else {
        ESP_LOGE(TAG, "Errore nella generazione della stringa JSON");
    }
    return ESP_OK;
}