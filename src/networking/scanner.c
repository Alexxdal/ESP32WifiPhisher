#include <esp_log.h>
#include "scanner.h"
#include "esp_netif.h"
#include "esp_netif_net_stack.h"
#include "lwip/etharp.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "cJSON.h"
#include "networking.h"
#include "dns.h"
#include "mdns.h"
#include "utils.h"
/* Raw ip operation */
#include "lwip/raw.h"
#include "lwip/tcp.h"
#include "lwip/ip.h"
#include "lwip/inet_chksum.h"
#include "lwip/tcpip.h"
#include "lwip/prot/tcp.h"
#include "lwip/prot/ip4.h"

static const char *TAG = "SCANNER";

static struct raw_pcb *g_raw_pcb = NULL;
static EventGroupHandle_t scanner_event_group = NULL;

#define SCAN_DEFAULT_TIMEOUT_MS     200
#define RAW_PACKET_SRC_PORT         12345
#define PORT_OPEN_BIT               BIT0  // SYN-ACK
#define PORT_CLOSED_BIT             BIT1  // RST


static u8_t receive_raw_callback(void *arg, struct raw_pcb *pcb, struct pbuf *p, const ip_addr_t *addr)
{
    struct ip_hdr *iphdr = (struct ip_hdr *)p->payload;
    u16_t iphdr_hlen = IPH_HL_BYTES(iphdr);

    if (p->len >= iphdr_hlen + sizeof(struct tcp_hdr)) 
    {
        struct tcp_hdr *tcphdr = (struct tcp_hdr *)((u8_t *)p->payload + iphdr_hlen);

        if (lwip_ntohs(tcphdr->dest) == RAW_PACKET_SRC_PORT) {
            uint8_t flags = TCPH_FLAGS(tcphdr);
            if ((flags & TCP_SYN) && (flags & TCP_ACK)) {
                if (scanner_event_group != NULL) {
                    xEventGroupSetBits(scanner_event_group, PORT_OPEN_BIT);
                }
            } 
            else if (flags & TCP_RST) {
                if (scanner_event_group != NULL) {
                    xEventGroupSetBits(scanner_event_group, PORT_CLOSED_BIT);
                }
            }
        }
    }
    return 0;
}


esp_err_t scanner_init(void)
{
    #ifdef DEBUG
    esp_log_level_set(TAG, ESP_LOG_DEBUG);
    #else
    esp_log_level_set(TAG, ESP_LOG_ERROR);
    #endif

    scanner_event_group = xEventGroupCreate();
    if (scanner_event_group == NULL) {
        return ESP_ERR_NO_MEM;
    }
    xEventGroupClearBits(scanner_event_group, PORT_OPEN_BIT | PORT_CLOSED_BIT);

    LOCK_TCPIP_CORE();
    g_raw_pcb = raw_new(IP_PROTO_TCP);
    if (g_raw_pcb) {
        raw_recv(g_raw_pcb, receive_raw_callback, NULL);
        raw_bind(g_raw_pcb, IP_ADDR_ANY);
    }
    UNLOCK_TCPIP_CORE();

    if (g_raw_pcb == NULL) {
        vEventGroupDelete(scanner_event_group);
        return ESP_ERR_NO_MEM;
    }

    if(mdns_init() != ESP_OK) {
        ESP_LOGW(TAG, "mDNS init failed, mdns_discover() won't work");
    }

    return ESP_OK;
}


esp_err_t scanner_deinit(void)
{
    LOCK_TCPIP_CORE();
    if (g_raw_pcb != NULL) {
        raw_remove(g_raw_pcb);
        g_raw_pcb = NULL;
    }
    UNLOCK_TCPIP_CORE();

    if (scanner_event_group != NULL) {
        vEventGroupDelete(scanner_event_group);
        scanner_event_group = NULL;
    }

    return ESP_OK;
}


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
    const uint32_t WAIT_MS = 100;
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
                    cJSON_AddStringToObject(result_obj, "vendor", resolve_mac_oui(eth_ret->addr));

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


static void send_custom_raw_packet(const ip_addr_t *my_ip, const ip_addr_t *target_ip, uint16_t port)
{
    if (g_raw_pcb == NULL) return;

    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, sizeof(struct tcp_hdr), PBUF_RAM);
    if (p == NULL) return;

    struct tcp_hdr *tcphdr = (struct tcp_hdr *)p->payload;
    memset(tcphdr, 0, sizeof(struct tcp_hdr));

    tcphdr->src    = lwip_htons(RAW_PACKET_SRC_PORT);
    tcphdr->dest   = lwip_htons(port);
    tcphdr->seqno  = lwip_htonl(1000);
    TCPH_HDRLEN_FLAGS_SET(tcphdr, 5, TCP_SYN);
    tcphdr->wnd    = lwip_htons(8192);
    tcphdr->chksum = 0;
    tcphdr->chksum = ip_chksum_pseudo(p, IP_PROTO_TCP, p->len, my_ip, target_ip);

    LOCK_TCPIP_CORE();
    raw_sendto(g_raw_pcb, p, target_ip);
    UNLOCK_TCPIP_CORE();

    pbuf_free(p);
}


static esp_err_t port_scan_connect(ip4_addr_t target, uint16_t port, uint32_t timeout_ms) 
{
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (sock < 0) {
        return PORT_ERROR;
    }

    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = target.addr;
    dest_addr.sin_port = htons(port);

    int res = connect(sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

    if (res < 0 && errno == EINPROGRESS) {
        fd_set fdset;
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);

        struct timeval timeout;
        timeout.tv_sec = timeout_ms / 1000;
        timeout.tv_usec = (timeout_ms % 1000) * 1000;
        res = select(sock + 1, NULL, &fdset, NULL, &timeout);

        if (res == 1) {
            int so_error = 0;
            socklen_t len = sizeof(so_error);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
            
            if (so_error == 0) {
                res = 0; 
            } else {
                // Connection Refused / RST
                res = -1;
            }
        } else {
            // Select error
            res = -1;
        }
    }

    close(sock);

    if (res == 0) {
        ESP_LOGD(TAG, "Porta %d: APERTA", port);
        return PORT_OPEN;
    } else {
        ESP_LOGD(TAG, "Porta %d: CHIUSA o FILTRATA", port);
        return PORT_CLOSED; 
    }
}


static esp_err_t port_scan_syn(ip4_addr_t target, uint16_t port, uint32_t timeout_ms)
{
    //Get local IP
    esp_netif_ip_info_t *sta_ip = networking_get_ip_info();
    esp_netif_t *esp_netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");

    if (esp_netif == NULL || sta_ip == NULL) {
        ESP_LOGE(TAG, "Wifi Interface not ready.");
        return ESP_ERR_INVALID_STATE;
    }

    if (scanner_event_group == NULL) {
        return ESP_ERR_NO_MEM;
    }
    xEventGroupClearBits(scanner_event_group, PORT_OPEN_BIT | PORT_CLOSED_BIT);

    ip_addr_t my_ip;
    ip_addr_copy_from_ip4(my_ip, sta_ip->ip);
    
    ip_addr_t target_ip;
    ip_addr_copy_from_ip4(target_ip, target);

    send_custom_raw_packet(&my_ip, &target_ip, port);

    EventBits_t bits = xEventGroupWaitBits(
        scanner_event_group, 
        PORT_OPEN_BIT | PORT_CLOSED_BIT, 
        pdTRUE,         // Clear on exit
        pdFALSE,        // Wait for ANY bit (non tutti insieme)
        pdMS_TO_TICKS(timeout_ms)
    );

    esp_err_t scan_result = PORT_CLOSED;
    if (bits & PORT_OPEN_BIT) {
        ESP_LOGD(TAG, "Porta %d: APERTA", port);
        scan_result = PORT_OPEN;
    } 
    else if (bits & PORT_CLOSED_BIT) {
        ESP_LOGD(TAG, "Porta %d: CHIUSA", port);
        scan_result = PORT_CLOSED;
    } 
    else {
        ESP_LOGD(TAG, "Porta %d: FILTRATA / TIMEOUT", port);
        scan_result = PORT_FILTERED;
    }

    return scan_result;
}


esp_err_t port_scan(ip4_addr_t target, uint16_t port, uint32_t timeout_ms, port_scan_method_t method)
{
    esp_err_t err = PORT_ERROR;

    if(timeout_ms == 0) {
        timeout_ms = SCAN_DEFAULT_TIMEOUT_MS;
    }

    switch(method) 
    {
        case TCP_CONNECT_SCAN:
            err = port_scan_connect(target, port, timeout_ms);
            break;
        
        case TCP_SYN_SCAN:
            err = port_scan_syn(target, port, timeout_ms);
            break;

        case TCP_FIN_SCAN:
        case TCP_NULL_SCAN:
        case TCP_XMAS_SCAN:
        case TCP_ACK_SCAN:
        case UDP_SCAN:
            break;

        default:
            err = port_scan_connect(target, port, timeout_ms);
            break;
    }

    return err;
}