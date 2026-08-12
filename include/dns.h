#ifndef _DNS_H
#define _DNS_H


#include "lwip/ip.h"

/**
 * @brief Start dns server to mimic captive portal
 * 
 */
void dns_server_start(void);


/**
 * @brief Stop dns server to mimic captive portal
 * 
 */
void dns_server_stop(void);


/**
 * @brief Resolve hostname from IP using specified DNS server
 * 
 * @param target_ip The IP address to resolve
 * @param dns_server The DNS server to query
 * @param out_name Buffer to store the resolved hostname
 * @param max_len Maximum length of the output buffer
 */
void dns_reverse_lookup(ip4_addr_t target_ip, ip4_addr_t dns_server, char *out_name, size_t max_len);

#endif