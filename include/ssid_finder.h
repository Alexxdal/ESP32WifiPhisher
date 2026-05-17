#ifndef _SSID_FINDER_H
#define _SSID_FINDER_H

#include <stdint.h>
#include <esp_err.h>
#include "sniffer.h"
#include <libwifi.h>


esp_err_t ssid_finder_start(target_info_t *target_info);


esp_err_t ssid_finder_stop(void);


#endif // _SSID_FINDER_H