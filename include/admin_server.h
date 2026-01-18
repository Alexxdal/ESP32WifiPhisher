#ifndef _ADMIN_SERVER_H
#define _ADMIN_SERVER_H

#include <esp_system.h>

/**
 * @brief Start http server task
 * 
 */
void http_admin_server_start(void);


/**
 * @brief Stop the http admin server
 * 
 */
void http_admin_server_stop(void);

#endif