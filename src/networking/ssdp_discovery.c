#include <string.h>
#include <strings.h>
#include <esp_log.h>
#include <esp_timer.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "cJSON.h"
#include "scanner.h"

static const char *TAG = "SSDP_DISCOVERY";

#define SSDP_MULTICAST_ADDR   "239.255.255.250"
#define SSDP_PORT             1900
#define SSDP_LISTEN_MS        2500
#define SSDP_RX_BUF_SZ        1024
#define SSDP_MAX_RESULTS      32

/*
 * Standard M-SEARCH request. MX is the max seconds a responder should wait
 * before answering (spread out on purpose to avoid every device replying at
 * once). ST=ssdp:all asks every UPnP device on the network to identify itself,
 * rather than filtering to a single service/device type.
 */
static const char *SSDP_MSEARCH =
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "MAN: \"ssdp:discover\"\r\n"
    "MX: 2\r\n"
    "ST: ssdp:all\r\n"
    "\r\n";

/**
 * @brief Pull the value of an HTTP-style header out of a raw SSDP response.
 *        Case-insensitive on the header name, per RFC.
 */
static bool extract_header(const char *resp, const char *header, char *out, size_t out_sz)
{
    const char *p = resp;
    size_t header_len = strlen(header);

    while (p && *p) {
        if (strncasecmp(p, header, header_len) == 0 && p[header_len] == ':') {
            p += header_len + 1;
            while (*p == ' ') p++;

            const char *end = strstr(p, "\r\n");
            size_t len = end ? (size_t)(end - p) : strlen(p);
            if (len >= out_sz) len = out_sz - 1;

            memcpy(out, p, len);
            out[len] = '\0';
            return true;
        }
        p = strstr(p, "\r\n");
        if (p) p += 2;
    }
    return false;
}

char* ssdp_discover(void)
{
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        ESP_LOGE(TAG, "Failed to create UDP socket");
        return NULL;
    }

    /* Non-blocking so the receive loop can poll against a wall-clock deadline
     * instead of blocking forever on a device that never answers. */
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in dest_addr = {0};
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(SSDP_PORT);
    inet_pton(AF_INET, SSDP_MULTICAST_ADDR, &dest_addr.sin_addr);

    int sent = sendto(sock, SSDP_MSEARCH, strlen(SSDP_MSEARCH), 0,
                       (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (sent < 0) {
        ESP_LOGE(TAG, "Failed to send M-SEARCH request");
        close(sock);
        return NULL;
    }

    cJSON *result_array = cJSON_CreateArray();
    if (result_array == NULL) {
        close(sock);
        return NULL;
    }

    char rx_buf[SSDP_RX_BUF_SZ];
    int64_t deadline_us = esp_timer_get_time() + ((int64_t)SSDP_LISTEN_MS * 1000);
    int count = 0;

    while (esp_timer_get_time() < deadline_us && count < SSDP_MAX_RESULTS) {
        struct sockaddr_in from_addr;
        socklen_t from_len = sizeof(from_addr);

        int len = recvfrom(sock, rx_buf, sizeof(rx_buf) - 1, 0,
                            (struct sockaddr *)&from_addr, &from_len);

        if (len > 0) {
            rx_buf[len] = '\0';

            char location[128] = "N/A";
            char server[96]    = "N/A";
            char usn[128]      = "N/A";

            extract_header(rx_buf, "LOCATION", location, sizeof(location));
            extract_header(rx_buf, "SERVER", server, sizeof(server));
            extract_header(rx_buf, "USN", usn, sizeof(usn));

            cJSON *obj = cJSON_CreateObject();
            cJSON_AddStringToObject(obj, "ip", inet_ntoa(from_addr.sin_addr));
            cJSON_AddStringToObject(obj, "location", location);
            cJSON_AddStringToObject(obj, "server", server);
            cJSON_AddStringToObject(obj, "usn", usn);
            cJSON_AddItemToArray(result_array, obj);
            count++;
        } else {
            /* Nothing pending right now, yield instead of busy-spinning */
            vTaskDelay(pdMS_TO_TICKS(50));
        }
    }

    close(sock);

    char *out = cJSON_PrintUnformatted(result_array);
    cJSON_Delete(result_array);
    return out;
}