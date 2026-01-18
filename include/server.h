#ifndef _SERVER_H
#define _SERVER_H

typedef enum 
{
    FIRMWARE_UPGRADE = 0,
    WEB_NET_MANAGER,
    PLUGIN_UPDATE,
    OAUTH_LOGIN
} attack_scheme_t;


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