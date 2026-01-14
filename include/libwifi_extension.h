#ifndef _LIBWIFI_EXTENSION_H_
#define _LIBWIFI_EXTENSION_H_

#include <esp_system.h>
#include "libwifi.h"


/**
 * @brief Channel Switch Announcement event structure
 * 
 */
typedef struct {
    bool     extended;       // true se ECSA
    uint8_t  mode;           // channel switch mode
    uint8_t  new_channel;    // destination channel
    uint8_t  count;          // countdown
    uint8_t  new_reg_class;  // solo ECSA (0 se CSA)
} csa_event_t;


/**
 * @brief Extract Channel Switch Announcement (CSA) or Extended Channel Switch Announcement (ECSA) from BSS info
 * 
 * @param bss Pointer to libwifi_bss structure
 * @param out Pointer to csa_event_t structure to store the extracted information
 * @return true if CSA/ECSA found and extracted, false otherwise
 */
bool libwifi_extract_csa(const struct libwifi_bss *bss, csa_event_t *out);


/**
 * @brief Find EAPOL frame in buffer
 * 
 * @param buffer 
 * @param len 
 * @param eapol_len 
 * @return uint8_t
 */
uint8_t *find_eapol_frame(uint8_t *buffer, uint16_t len, uint16_t *eapol_len);


/**
 * @brief Extract CSA/ECSA from a management action frame
 * 
 * @param f Pointer to libwifi_frame structure
 * @param out Pointer to csa_event_t structure to store the extracted information
 * @return true if CSA/ECSA found and extracted, false otherwise
 */
bool libwifi_extract_csa_from_action_frame(const struct libwifi_frame *f, csa_event_t *out);

#endif /* _LIBWIFI_EXTENSION_H_ */