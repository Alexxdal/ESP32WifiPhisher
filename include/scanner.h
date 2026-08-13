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

#endif /* _SCANNER_H */