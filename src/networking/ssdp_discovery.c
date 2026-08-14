#include <stdlib.h>
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


/**
 * @brief Split a "http://host[:port]/path" URL (as found in an SSDP LOCATION
 *        header) into its parts. LAN UPnP LOCATION URLs always use a raw IP
 *        for the host, never a DNS name, so this deliberately does not try
 *        to resolve hostnames.
 */
static bool parse_http_url(const char *url, char *host, size_t host_sz, uint16_t *port, char *path, size_t path_sz)
{
    if (strncmp(url, "http://", 7) != 0) return false;
    const char *p = url + 7;
    if (*p == '\0') return false;

    const char *path_start = strchr(p, '/');
    const char *host_end = path_start ? path_start : (p + strlen(p));

    const char *colon = memchr(p, ':', (size_t)(host_end - p));
    size_t hlen = colon ? (size_t)(colon - p) : (size_t)(host_end - p);
    if (hlen == 0 || hlen >= host_sz) return false;
    memcpy(host, p, hlen);
    host[hlen] = '\0';

    *port = colon ? (uint16_t)atoi(colon + 1) : 80;
    if (*port == 0) *port = 80;

    strlcpy(path, path_start ? path_start : "/", path_sz);
    return true;
}


/**
 * @brief Decode the handful of XML entities that show up in real-world
 *        friendlyName/manufacturer/modelName values (e.g. "Alex's Router").
 *        In-place, shrinks the string as needed.
 */
static void xml_decode_entities(char *s)
{
    static const struct { const char *entity; char ch; } map[] = {
        { "&amp;", '&' }, { "&lt;", '<' }, { "&gt;", '>' },
        { "&quot;", '"' }, { "&apos;", '\'' }
    };
    char *read = s, *write = s;
    while (*read) {
        bool matched = false;
        for (size_t i = 0; i < sizeof(map) / sizeof(map[0]); i++) {
            size_t elen = strlen(map[i].entity);
            if (strncmp(read, map[i].entity, elen) == 0) {
                *write++ = map[i].ch;
                read += elen;
                matched = true;
                break;
            }
        }
        if (!matched) {
            *write++ = *read++;
        }
    }
    *write = '\0';
}


/**
 * @brief Grab the text content of the first <tag>...</tag> occurrence in an
 *        XML document. Deliberately not a real XML parser (no namespaces,
 *        no attribute handling, no nesting awareness) - just enough to pull
 *        flat leaf values out of a UPnP device description document.
 */
static void extract_xml_tag(const char *xml, const char *tag, char *out, size_t out_sz)
{
    out[0] = '\0';
    char open_tag[40];
    snprintf(open_tag, sizeof(open_tag), "<%s>", tag);
    const char *start = strstr(xml, open_tag);
    if (!start) return;
    start += strlen(open_tag);

    char close_tag[40];
    snprintf(close_tag, sizeof(close_tag), "</%s>", tag);
    const char *end = strstr(start, close_tag);
    if (!end || end < start) return;

    size_t len = (size_t)(end - start);
    if (len >= out_sz) len = out_sz - 1;
    memcpy(out, start, len);
    out[len] = '\0';
    xml_decode_entities(out);
}


/**
 * @brief Non-blocking connect() with a wall-clock timeout, mirroring the
 *        same pattern used by port_scan_connect() in scanner.c.
 */
static int connect_with_timeout(int sock, struct sockaddr_in *dest, int timeout_ms)
{
    int orig_flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, orig_flags | O_NONBLOCK);

    int res = connect(sock, (struct sockaddr *)dest, sizeof(*dest));
    if (res < 0 && errno == EINPROGRESS) {
        fd_set fdset;
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        res = select(sock + 1, NULL, &fdset, NULL, &tv);
        if (res == 1) {
            int so_error = 0;
            socklen_t len = sizeof(so_error);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
            res = (so_error == 0) ? 0 : -1;
        } else {
            res = -1;
        }
    }

    fcntl(sock, F_SETFL, orig_flags); /* back to blocking for send()/recv() */
    return res;
}


bool ssdp_fetch_device_info(const char *location, char *friendly_name, size_t fn_sz,
                             char *manufacturer, size_t mf_sz, char *model, size_t model_sz)
{
    friendly_name[0] = '\0';
    manufacturer[0] = '\0';
    model[0] = '\0';

    if (!location || strcmp(location, "N/A") == 0) return false;

    char host[64];
    char path[128];
    uint16_t port;
    if (!parse_http_url(location, host, sizeof(host), &port, path, sizeof(path))) {
        return false;
    }

    struct sockaddr_in dest = {0};
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &dest.sin_addr) != 1) {
        return false; /* LOCATION host wasn't a raw IP - not expected on a LAN */
    }

    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) return false;

    struct timeval tv = { .tv_sec = 1, .tv_usec = 200000 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect_with_timeout(sock, &dest, 800) != 0) {
        close(sock);
        return false;
    }

    char req[320];
    int req_len = snprintf(req, sizeof(req),
        "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: ESP32WifiPhisher\r\n\r\n",
        path, host);
    /* snprintf() returns the length that *would* have been written even if
     * truncated - clamp before send() so a pathological long path/host
     * can't turn into an out-of-bounds read on the stack buffer. */
    if (req_len <= 0) {
        close(sock);
        return false;
    }
    if ((size_t)req_len >= sizeof(req)) {
        req_len = sizeof(req) - 1;
    }
    if (send(sock, req, req_len, 0) < 0) {
        close(sock);
        return false;
    }

    const size_t buf_sz = 3072;
    char *rx_buf = malloc(buf_sz);
    if (!rx_buf) {
        close(sock);
        return false;
    }

    size_t total = 0;
    int len;
    while (total < buf_sz - 1 &&
           (len = recv(sock, rx_buf + total, buf_sz - 1 - total, 0)) > 0) {
        total += (size_t)len;
    }
    close(sock);
    rx_buf[total] = '\0';

    /* Skip past the HTTP response headers to the XML body */
    char *body = strstr(rx_buf, "\r\n\r\n");
    body = body ? body + 4 : rx_buf;

    extract_xml_tag(body, "friendlyName", friendly_name, fn_sz);
    extract_xml_tag(body, "manufacturer", manufacturer, mf_sz);
    extract_xml_tag(body, "modelName", model, model_sz);

    free(rx_buf);

    return friendly_name[0] != '\0';
}