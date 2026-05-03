#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "lwip/lwip_napt.h"
#include "lwip/ip4_addr.h"
#include "lwip/err.h"
#include "portmap.h"

static const char *TAG_NAT = "DNAT";

esp_err_t setup_dnat_for_captive_portal(void)
{
    // 1. Get the netif of the SoftAP interface
    esp_netif_t *ap_netif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
    if (ap_netif == NULL) {
        ESP_LOGE(TAG_NAT, "Error: failed to get AP netif");
        return ESP_FAIL;
    }

    // Estrai l'indirizzo IP corrente del nostro SoftAP in modo corretto per ESP-IDF
    esp_netif_ip_info_t ip_info;
    if (esp_netif_get_ip_info(ap_netif, &ip_info) != ESP_OK) {
        ESP_LOGE(TAG_NAT, "Error: failed to get AP IP info");
        return ESP_FAIL;
    }

    // 2. Enable NAPT (Network Address Port Translation) on the AP interface
    // L'indirizzo IP deve essere passato in formato uint32_t. 
    // ip_napt_enable è di tipo 'void' nelle versioni recenti, quindi la chiamiamo direttamente.
    ip_napt_enable(ip_info.ip.addr, 1);
    ESP_LOGI(TAG_NAT, "NAPT Enabled on AP interface");

    // 3. Set DNAT rules (Port Forwarding)
    
    // IP address of our ESP32 (the redirect target)
    ip4_addr_t esp_ip;
    esp_ip.addr = ip_info.ip.addr; // Usiamo lo stesso IP appena estratto (es. 192.168.4.1)

    // Dummy IP address to represent "any IP" (0.0.0.0)
    ip4_addr_t any_ip;
    IP4_ADDR(&any_ip, 0, 0, 0, 0);

    /* 
     * Rule 1: DNS (UDP port 53)
     * Redirect ANY UDP packet destined for port 53 to our IP (192.168.4.1:53)
     */
    uint8_t idx_dns = ip_portmap_add(IPPROTO_UDP, any_ip.addr, 53, esp_ip.addr, 53);
    // Controlliamo che l'indice non sia 0xFF (255), che significa "Tabella piena" o "Errore"
    if (idx_dns != 0xFF) {
        ESP_LOGI(TAG_NAT, "DNS (UDP 53) -> 192.168.4.1:53 configured (Index: %d)", idx_dns);
    } else {
        ESP_LOGE(TAG_NAT, "Error configuring DNS");
        return ESP_FAIL;
    }
    /* 
     * Rule 2: HTTP (TCP port 80)
     * If the user types "http://8.8.8.8" or a random IP in the browser, 
     * this rule forces the traffic to your web server.
     */
    uint8_t idx_http = ip_portmap_add(IPPROTO_TCP, any_ip.addr, 80, esp_ip.addr, 80);
    if (idx_http != 0xFF) {
        ESP_LOGI(TAG_NAT, "HTTP (TCP 80) -> 192.168.4.1:80 configured (Index: %d)", idx_http);
    } else {
        ESP_LOGE(TAG_NAT, "Error configuring HTTP");
        return ESP_FAIL;
    }
    
    return ESP_OK;
}