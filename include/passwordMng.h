#ifndef _PASSWORD_MNG_H
#define _PASSWORD_MNG_H

#include "esp_system.h"

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


#endif