#include <string.h>
#include <esp_log.h>
#include "mdns.h"
#include "cJSON.h"
#include "scanner.h"

static const char *TAG = "MDNS_DISCOVERY";

/*
 * Common service types worth probing on a home/office LAN.
 * Each entry costs one extra query round-trip (MDNS_QUERY_TIMEOUT_MS each),
 * so keep this list scoped to what's actually useful for recon.
 */
static const char *SERVICE_TYPES[] = {
    "_http",         // Web UIs (routers, NAS, IoT panels, printers admin page)
    "_ipp",          // Network printers (AirPrint / IPP)
    "_googlecast",   // Chromecast / Google Home / Google Nest
    "_airplay",      // AirPlay video receivers (Apple TV, smart TVs)
    "_raop",         // AirPlay audio (speakers, older devices)
    "_ssh",          // SSH-enabled hosts
    "_smb",          // SMB / file sharing (macOS, NAS)
    "_workstation",  // Generic OS presence beacon (macOS/Linux)
};
#define SERVICE_TYPES_COUNT (sizeof(SERVICE_TYPES) / sizeof(SERVICE_TYPES[0]))

#define MDNS_QUERY_TIMEOUT_MS   700
#define MDNS_MAX_RESULTS_PER_Q  16

char* mdns_discover(void)
{
    cJSON *result_array = cJSON_CreateArray();
    if (result_array == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < SERVICE_TYPES_COUNT; i++) {
        mdns_result_t *results = NULL;

        esp_err_t err = mdns_query_ptr(SERVICE_TYPES[i], "_tcp",
                                        MDNS_QUERY_TIMEOUT_MS,
                                        MDNS_MAX_RESULTS_PER_Q, &results);

        if (err != ESP_OK) {
            /* ESP_ERR_NOT_FOUND just means "nobody answered", not a real error */
            if (err != ESP_ERR_NOT_FOUND) {
                ESP_LOGW(TAG, "Query failed for %s: %s", SERVICE_TYPES[i], esp_err_to_name(err));
            }
            continue;
        }

        for (mdns_result_t *r = results; r != NULL; r = r->next) {
            cJSON *obj = cJSON_CreateObject();

            cJSON_AddStringToObject(obj, "hostname", r->hostname ? r->hostname : "N/A");
            cJSON_AddStringToObject(obj, "instance_name", r->instance_name ? r->instance_name : "N/A");
            cJSON_AddStringToObject(obj, "service", SERVICE_TYPES[i]);
            cJSON_AddNumberToObject(obj, "port", r->port);

            /* Grab the first IPv4 address in the answer, if any */
            char ip_str[16] = "N/A";
            for (mdns_ip_addr_t *addr = r->addr; addr != NULL; addr = addr->next) {
                if (addr->addr.type == ESP_IPADDR_TYPE_V4) {
                    esp_ip4addr_ntoa(&addr->addr.u_addr.ip4, ip_str, sizeof(ip_str));
                    break;
                }
            }
            cJSON_AddStringToObject(obj, "ip", ip_str);

            cJSON_AddItemToArray(result_array, obj);
        }

        mdns_query_results_free(results);
    }

    char *out = cJSON_PrintUnformatted(result_array);
    cJSON_Delete(result_array);
    return out;
}