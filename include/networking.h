#ifndef _NETWORKING_H_
#define _NETWORKING_H_

#include <esp_err.h>
#include <esp_netif.h>

/**
 * @brief Initializes the networking subsystem.
 */
esp_err_t networking_init(void);


/**
 * @brief Checks if the station interface has obtained an IP address.
 * 
 * @return true if the station has an IP address, false otherwise.
 */
bool networking_has_ip(void);


/**
 * @brief Retrieves the current IP information of the station interface.
 * 
 * @return esp_netif_ip_info_t* containing the IP address, netmask, and gateway.
 */
esp_netif_ip_info_t *networking_get_ip_info(void);


#endif /* _NETWORKING_H_ */