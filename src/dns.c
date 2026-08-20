#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "lwip/err.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"
#include "esp_random.h"
#include "dns.h"
#include "TaskManager.h"

#define DNS_PORT 53
#define DNS_TIMEOUT_MS 500
#define RESPONSE_IP_ADDR {192, 168, 4, 1}
static const char *TAG = "DNS_SERVER";
static TaskHandle_t dns_server_task_handle = NULL;
static volatile bool dns_server_running = false;
static SemaphoreHandle_t dns_server_stopped_sem = NULL;

static void dns_server_task(void *pvParameters)
{
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    char buf[512];
    int sock;

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        ESP_LOGD(TAG, "Failed to create DNS socket");
        goto cleanup_no_socket;
    }

    // Allow quick rebind on the same port after a restart
    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    // recvfrom() times out periodically so dns_server_running can be re-checked
    struct timeval timeout;
    timeout.tv_sec = DNS_TIMEOUT_MS / 1000;
    timeout.tv_usec = (DNS_TIMEOUT_MS % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(DNS_PORT);

    if (bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        ESP_LOGE(TAG, "Failed to bind DNS socket");
        goto cleanup;
    }
    ESP_LOGD(TAG, "DNS server listening on port %d", DNS_PORT);

    uint8_t response_template[] = {
        0x00, 0x00, // ID (copied from the request)
        0x81, 0x80, // Flags: response, no error
        0x00, 0x01, // QDCOUNT (1 question)
        0x00, 0x01, // ANCOUNT (1 answer)
        0x00, 0x00, // NSCOUNT
        0x00, 0x00, // ARCOUNT
        // Answer record appended below
    };
    const uint8_t ip_address[] = RESPONSE_IP_ADDR;

    while (dns_server_running)
    {
        int len = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&client_addr, &client_addr_len);
        if (len < 12) {
            continue;
        }

        // Find the end of QNAME instead of assuming QTYPE/QCLASS are the
        // last 4 bytes of the packet (breaks with EDNS0/OPT records).
        int pos = 12;
        bool malformed = false;
        while (pos < len && buf[pos] != 0) {
            if (((uint8_t)buf[pos] & 0xC0) == 0xC0) {
                pos += 2;
                goto qname_done;
            }
            pos += (uint8_t)buf[pos] + 1;
            if (pos >= len) {
                malformed = true;
                break;
            }
        }
        pos++; // skip QNAME terminator
    qname_done:
        if (malformed || pos + 4 > len) {
            continue; // malformed/incomplete packet
        }

        uint16_t qtype = ((uint8_t)buf[pos] << 8) | (uint8_t)buf[pos + 1];
        int qsection_len = (pos + 4) - 12; // actual length of QNAME+QTYPE+QCLASS

        // Ignore AAAA (IPv6) queries so Windows falls back to A quickly
        if (qtype == 28) {
            continue;
        }

        // Only answer A (1) or ANY (255) queries
        if (qtype != 1 && qtype != 255) {
            continue;
        }

        // Copy ID from the request
        response_template[0] = buf[0];
        response_template[1] = buf[1];
        response_template[7] = 1; // ANCOUNT = 1

        uint8_t response[512];
        memcpy(response, response_template, sizeof(response_template));
        int response_len = sizeof(response_template);

        // Copy only the real Question section, never trailing records
        // such as an EDNS0 OPT (source of the old overflow/ARCOUNT bug).
        memcpy(&response[response_len], &buf[12], qsection_len);
        response_len += qsection_len;

        uint8_t answer[] = {
            0xC0, 0x0C, // Pointer to the query name
            0x00, 0x01, // Type: A
            0x00, 0x01, // Class: IN
            0x00, 0x00, 0x00, 0x3C, // TTL: 60s
            0x00, 0x04, // Data length: 4 bytes (IPv4)
            ip_address[0], ip_address[1], ip_address[2], ip_address[3]
        };

        // Explicit safety net against overflow
        if (response_len + (int)sizeof(answer) > (int)sizeof(response)) {
            continue;
        }
        memcpy(&response[response_len], answer, sizeof(answer));
        response_len += sizeof(answer);

        sendto(sock, response, response_len, 0, (struct sockaddr *)&client_addr, client_addr_len);
    }

cleanup:
    close(sock);
cleanup_no_socket:
    dns_server_task_handle = NULL;
    if (dns_server_stopped_sem != NULL) {
        xSemaphoreGive(dns_server_stopped_sem);
    }
    task_manager_unregister_current_task();
    vTaskDelete(NULL);
}


void dns_server_start(void)
{
    if (dns_server_task_handle != NULL)
    {
        ESP_LOGE(TAG, "DNS Server already started.");
        return;
    }
    if (dns_server_stopped_sem == NULL) {
        dns_server_stopped_sem = xSemaphoreCreateBinary();
    } else {
        xSemaphoreTake(dns_server_stopped_sem, 0); // clear stale signal, if any
    }
    dns_server_running = true;
    task_manager_create_task(dns_server_task, "dns_server_task", 4096, NULL, 5, &dns_server_task_handle);
}


void dns_server_stop(void)
{
    if (dns_server_task_handle == NULL)
    {
        ESP_LOGE(TAG, "DNS Server task is not running.");
        return;
    }
    dns_server_running = false;

    // Wait for the task to actually signal its exit instead of a fixed
    // delay, to avoid racing a subsequent start() on the port-53 bind.
    if (dns_server_stopped_sem != NULL) {
        if (xSemaphoreTake(dns_server_stopped_sem, pdMS_TO_TICKS(DNS_TIMEOUT_MS + 500)) != pdTRUE) {
            ESP_LOGW(TAG, "Timeout waiting for DNS task to stop");
        }
    }
    dns_server_task_handle = NULL;
}


// timeout_ms/max_attempts let callers doing many lookups back-to-back (e.g. a
// subnet scan) use a much shorter budget than the 3x10s default, which is
// tuned for a single one-off lookup over the internet, not a fast LAN.
void dns_reverse_lookup_ex(ip4_addr_t target_ip, ip4_addr_t dns_server, char *out_name, size_t max_len, uint32_t timeout_ms, int max_attempts)
{
    snprintf(out_name, max_len, "N/A");
 
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        ESP_LOGD(TAG, "socket() failed, errno=%d", errno);
        return;
    }
 
    // Bind explicitly to the STA interface
    esp_netif_t *sta_netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (sta_netif == NULL) {
        ESP_LOGD(TAG, "STA netif not found");
        close(sock); return;
    }
    esp_netif_ip_info_t ip_info;
    if (esp_netif_get_ip_info(sta_netif, &ip_info) != ESP_OK) {
        ESP_LOGD(TAG, "Failed to read STA IP info");
        close(sock); return;
    }
    if (ip_info.ip.addr == 0) {
        ESP_LOGD(TAG, "STA has no valid IP yet");
        close(sock); return;
    }
 
    struct sockaddr_in local_addr = {
        .sin_family      = AF_INET,
        .sin_port        = htons(0),
        .sin_addr.s_addr = ip_info.ip.addr
    };
    if (bind(sock, (struct sockaddr *)&local_addr, sizeof(local_addr)) < 0) {
        ESP_LOGD(TAG, "bind() failed, errno=%d (%s)", errno, strerror(errno));
        close(sock); return;
    }
 
    struct sockaddr_in dest_addr = {
        .sin_family = AF_INET,
        .sin_port   = htons(53),
        .sin_addr.s_addr = dns_server.addr
    };
 
    uint8_t buffer[512] = {0};
 
    // Header
    buffer[0] = 0xAA; buffer[1] = 0xBB;
    buffer[2] = 0x01; buffer[3] = 0x00;
    buffer[5] = 0x01; // QDCOUNT = 1
 
    // Question: build x.x.x.x.in-addr.arpa
    uint8_t *ptr = &buffer[12];
    uint32_t ip = lwip_ntohl(target_ip.addr);
    char temp_buf[4];
    int len;
 
    for (int i = 0; i < 4; i++) {
        // Explicit cast to match the %lu format specifier
        len = snprintf(temp_buf, sizeof(temp_buf), "%lu", (unsigned long)((ip >> (i * 8)) & 0xFF));
        *ptr++ = len;
        memcpy(ptr, temp_buf, len);
        ptr += len;
    }
 
    // NOTE: \xHH hex escapes in C keep consuming hex digits, so
    // "\x04arpa" would be parsed as the single byte 0x4A ('a' is a valid
    // hex digit) instead of length-byte 0x04 followed by "arpa" — this was
    // silently corrupting the PTR query. Splitting into adjacent string
    // literals stops the escape at the literal boundary.
    const char *arpa_suffix = "\x07in-addr\x04" "arpa";
    memcpy(ptr, arpa_suffix, 14); // 8 ("in-addr" label) + 5 ("arpa" label) + 1 (implicit '\0' terminator)
    ptr += 14;
 
    *ptr++ = 0x00; *ptr++ = 0x0C; // QTYPE  = PTR
    *ptr++ = 0x00; *ptr++ = 0x01; // QCLASS = IN
 
    int request_len = ptr - buffer;
 
    // Send with retry
    int recv_len = 0;
    bool response_received = false;
 
    for (int attempt = 1; attempt <= max_attempts; attempt++) {
        if (sendto(sock, buffer, request_len, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
            ESP_LOGD(TAG, "Attempt %d: sendto failed, errno=%d", attempt, errno);
            continue;
        }
 
        // Wait for the socket to be readable via select(), then read with a
        // plain blocking recvfrom() (avoids relying on SO_RCVTIMEO directly).
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);
        struct timeval select_tv = { .tv_sec = timeout_ms / 1000, .tv_usec = (timeout_ms % 1000) * 1000 };
        if (select(sock + 1, &readfds, NULL, NULL, &select_tv) <= 0) {
            ESP_LOGD(TAG, "Attempt %d: no response", attempt);
            continue;
        }
 
        struct sockaddr_in source_addr;
        socklen_t socklen = sizeof(source_addr);
        recv_len = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&source_addr, &socklen);
        if (recv_len > 0) {
            response_received = true;
            break;
        }
    }
 
    if (!response_received) {
        ESP_LOGD(TAG, "No response from " IPSTR ":53 after %d attempts", IP2STR(&dns_server), max_attempts);
        close(sock); return;
    }
 
    // Check transaction ID and RCODE
    if (buffer[0] != 0xAA || buffer[1] != 0xBB) {
        ESP_LOGD(TAG, "Unexpected transaction ID: got 0x%02X%02X, expected 0xAABB", buffer[0], buffer[1]);
        close(sock); return;
    }
    int rcode = buffer[3] & 0x0F;
    if (rcode != 0) {
        ESP_LOGD(TAG, "Response RCODE=%d (1=FormErr 2=ServFail 3=NXDomain 5=Refused)", rcode);
        close(sock); return;
    }
 
    uint16_t answers = (buffer[6] << 8) | buffer[7]; // ANCOUNT is 16-bit
    if (answers == 0) {
        ESP_LOGD(TAG, "ANCOUNT=0: response has no PTR record");
        close(sock); return;
    }
 
    // Skip the response's Question section, starting at byte 12
    int idx = 12;
    uint16_t qdcount = (buffer[4] << 8) | buffer[5];
 
    for (int q = 0; q < qdcount && idx < recv_len; q++) {
        // Skip QNAME
        while (idx < recv_len) {
            if (buffer[idx] == 0) {
                idx++; // terminator
                break;
            }
            if ((buffer[idx] & 0xC0) == 0xC0) {
                idx += 2; // compression pointer
                break;
            }
            idx += buffer[idx] + 1;
        }
        idx += 4; // QTYPE + QCLASS
    }
 
    // idx now points to the start of the Answer section
    if ((buffer[idx] & 0xC0) == 0xC0) idx += 2;
    else {
        while (idx < recv_len && buffer[idx] != 0) {
            if ((buffer[idx] & 0xC0) == 0xC0) { idx += 2; goto parse_rdata; }
            idx += buffer[idx] + 1;
        }
        if (idx < recv_len) idx++;
    }
    parse_rdata:
 
    if (idx + 10 > recv_len) {
        ESP_LOGD(TAG, "Truncated/malformed answer (idx=%d recv_len=%d)", idx, recv_len);
        close(sock); return;
    }
 
    uint16_t type = (buffer[idx] << 8) | buffer[idx + 1];
    idx += 10; // Type(2) + Class(2) + TTL(4) + RDLENGTH(2)
 
    if (type != 12 || idx >= recv_len) {
        ESP_LOGD(TAG, "Unexpected record type: %d (expected 12=PTR)", type);
        close(sock); return;
    }
 
    // Decode the PTR name
    int out_idx = 0;
    int i = idx;
    int jumps = 0;
 
    while (i < recv_len && buffer[i] != 0 && out_idx < (int)(max_len - 1)) {
        if ((buffer[i] & 0xC0) == 0xC0) {
            if (++jumps > 5 || i + 1 >= recv_len) break;
            i = ((buffer[i] & 0x3F) << 8) | buffer[i + 1];
        } else {
            int label_len = buffer[i++];
            if (out_idx > 0) out_name[out_idx++] = '.';
            for (int j = 0; j < label_len && i < recv_len && out_idx < (int)(max_len - 1); j++)
                out_name[out_idx++] = buffer[i++];
        }
    }
    out_name[out_idx] = '\0';
    close(sock);
}
 

void dns_reverse_lookup(ip4_addr_t target_ip, ip4_addr_t dns_server, char *out_name, size_t max_len)
{
    dns_reverse_lookup_ex(target_ip, dns_server, out_name, max_len, 10000, 3);
}