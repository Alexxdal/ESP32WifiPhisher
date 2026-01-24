#ifndef _PASSWORD_MNG_H
#define _PASSWORD_MNG_H

#include "esp_http_server.h"


#define PASSWORD_FILE "/spiffs/passwords.txt"


/**
 * @brief Initialize password manager
 * 
 * @return esp_err_t 
 */
esp_err_t password_manager_init(void);


/**
 * @brief Save the input string
 * 
 * @param text 
 */
void password_manager_save(char *text);


/**
 * @brief Erase all file content
 * 
 */
void password_manager_clean(void);


/**
 * @brief Append new frame to pcap buffer
 * 
 * @param buffer 
 * @param len 
 * @param us 
 */
void password_manager_append_frame(const uint8_t *buffer, int len, int us);


/**
 * @brief Save pcap file to SPIFFS
 * 
 */
void password_manager_pcap_finalize(void);


/**
 * @brief Read password file and put output directly on web response
 * 
 * @param req 
 */
void password_manager_read_passwords(httpd_req_t *req);


#endif