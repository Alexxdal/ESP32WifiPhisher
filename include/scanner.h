#ifndef _SCANNER_H
#define _SCANNER_H

#include <esp_err.h>
#include "lwip/ip_addr.h"

typedef enum {
    TCP_CONNECT_SCAN = 0,
    TCP_SYN_SCAN,
    TCP_FIN_SCAN,
    TCP_NULL_SCAN,
    TCP_XMAS_SCAN,
    TCP_ACK_SCAN,
    UDP_SCAN,
    MAX_SCAN_METHOD
} port_scan_method_t;

typedef enum {
    PORT_OPEN = 0,
    PORT_CLOSED,
    PORT_FILTERED,
    PORT_ERROR
} port_state_t;

esp_err_t scanner_init(void);

esp_err_t scanner_deinit(void);

char* subnet_scan(void);

esp_err_t port_scan(ip4_addr_t target, uint16_t port, uint32_t timeout_ms, port_scan_method_t method);


/**
 * @brief Discover mDNS/Bonjour services on the local subnet (printers, Chromecast,
 *        AirPlay, SMB shares, generic hosts, ecc.) by querying a fixed list of
 *        common service types and collecting the responses.
 *
 * @note Requires mdns_init() to have been called once at startup (see main.c),
 *       after the STA/AP netif is up. This function only queries, it does not
 *       advertise the device itself.
 *
 * @return Newly heap-allocated JSON array string (caller must free()), or NULL
 *         on allocation failure. Returns "[]" if nothing responded.
 */
char* mdns_discover(void);


/**
 * @brief Discover UPnP/SSDP devices on the local subnet (routers, smart TVs,
 *        NAS, media servers, IoT hubs, ecc.) by sending an M-SEARCH multicast
 *        request and collecting the unicast replies for a fixed listen window.
 *
 * @note SSDP responses to M-SEARCH are unicast back to the sender per spec,
 *       so no IGMP multicast group join is required to receive them - only
 *       to send the initial request, which sendto() handles on its own.
 *
 * @return Newly heap-allocated JSON array string (caller must free()), or NULL
 *         on socket failure. Returns "[]" if nothing responded.
 */
char* ssdp_discover(void);

#endif /* _SCANNER_H */