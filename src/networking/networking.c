#include <string.h>
#include <esp_log.h>
#include <esp_system.h>
#include <esp_event.h>
#include <libwifi.h>
#include "networking.h"


static const char *TAG = "NETWORKING";
static bool station_got_ip = false;
static esp_netif_ip_info_t station_ip = {0};


static void ip_event_handler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data)
{
    if(event_base != IP_EVENT) return;

    if (event_id == IP_EVENT_STA_GOT_IP) 
    {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        memcpy(&station_ip, &event->ip_info, sizeof(esp_netif_ip_info_t));
        ESP_LOGI(TAG, "Device connected with IP: " IPSTR " Netmask: " IPSTR " Gateway: " IPSTR, IP2STR(&station_ip.ip), IP2STR(&station_ip.netmask), IP2STR(&station_ip.gw));
        station_got_ip = true;
    }
    else if (event_id == IP_EVENT_STA_LOST_IP)
    {
        ESP_LOGI(TAG, "Device lost IP address");
        station_got_ip = false;
        memset(&station_ip, 0, sizeof(esp_netif_ip_info_t));
    }
    else if (event_id == IP_EVENT_AP_STAIPASSIGNED)
    {
        ip_event_ap_staipassigned_t* event = (ip_event_ap_staipassigned_t*) event_data;
        ESP_LOGI(TAG, "Client connected to AP with IP " IPSTR " to Client ("MACSTR")", IP2STR(&event->ip), MAC2STR(event->mac));
    }
}


bool networking_has_ip(void) 
{
    return station_got_ip;
}


esp_netif_ip_info_t *networking_get_ip_info(void) 
{
    return &station_ip;
}


esp_err_t networking_init(void) 
{
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, ESP_EVENT_ANY_ID, &ip_event_handler, NULL, NULL));
    ESP_LOGI(TAG, "Networking module initialized");
    return ESP_OK;
}