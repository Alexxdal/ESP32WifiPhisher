#ifndef _SCANNER_H
#define _SCANNER_H

#include <esp_err.h>
#include <stdbool.h>
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


/**
 * @brief Fetch and parse a UPnP device description document (the URL given
 *        in an SSDP LOCATION header) to pull out the identity fields that
 *        raw SSDP headers don't carry - friendlyName (often a user-assigned
 *        name like "Fire TV di Stefano"), manufacturer, and modelName. This
 *        is what lets Host Discovery show the same kind of human name apps
 *        like Fing display, instead of just a raw device/service type.
 *
 * @note Does one small HTTP GET over a plain TCP socket (no esp_http_client
 *       dependency) with a short connect/recv timeout, so it's safe to call
 *       once per discovered UPnP host without stalling the scan for long.
 *
 * @return true if friendly_name was resolved (the only field considered
 *         mandatory - manufacturer/model are best-effort and may stay
 *         empty even on success).
 */
bool ssdp_fetch_device_info(const char *location, char *friendly_name, size_t fn_sz,
                             char *manufacturer, size_t mf_sz, char *model, size_t model_sz);

#endif /* _SCANNER_H */