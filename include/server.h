#ifndef _SERVER_H
#define _SERVER_H

#include "wifi_attacks.h"

/**
 * @brief Start http server task
 * 
 */
void http_attack_server_start(void);


/**
 * @brief Stop http server
 * 
 */
void http_attack_server_stop(void);

#endif