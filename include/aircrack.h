#ifndef _AIRCRACK_H
#define _AIRCRACK_H

#include <esp_system.h>


bool verify_password(const char *passphrase, const char *ssid, size_t ssid_len,
                     const uint8_t *mac_ap, const uint8_t *mac_sta,
                     const uint8_t *anonce, const uint8_t *snonce,
                     const uint8_t *eapol, size_t eapol_len,
                     const uint8_t *expected_mic, uint8_t key_descriptor);


bool verify_pmkid(const char *passphrase, const char *ssid, size_t ssid_len,
                  const uint8_t *mac_ap, const uint8_t *mac_sta,
                  const uint8_t *expected_pmkid);


#endif