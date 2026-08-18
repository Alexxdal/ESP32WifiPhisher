#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>
#include <string.h>
#include <stdio.h>
#include "esp_log.h"
#include "aircrack.h"

#define PMKID_LEN 16
#define WPA_PASSPHRASE_MAX_LEN 64
#define WPA_SSID_MAX_LEN 32
#define WPA_PTK_LEN 64
#define PTK_ALG_SHA1   0
#define PTK_ALG_SHA256 1

static const char *TAG = "AIRCRACK";


/* * OTTIMIZZAZIONE FLASH:
 * Importiamo le funzioni primitive già compilate in libwpa_supplicant.a per il Wi-Fi.
 * Evitiamo di includere il layer di astrazione generico di MbedTLS, risparmiando KB di flash.
 */
extern void hmac_md5(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t *mac);
extern void hmac_sha1(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t *mac);
extern void sha1_prf(const uint8_t *key, size_t key_len, const char *label, const uint8_t *data, size_t data_len, uint8_t *buf, size_t buf_len);
extern void sha256_prf(const uint8_t *key, size_t key_len, const char *label, const uint8_t *data, size_t data_len, uint8_t *buf, size_t buf_len);
extern int omac1_aes_128(const uint8_t *key, const uint8_t *data, size_t data_len, uint8_t *mac);


int calculate_pmk(const char *passphrase, const char *ssid, size_t ssid_len, uint8_t *pmk) 
{
    int ret = 0;
    ret = mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA1, (const unsigned char *)passphrase, strlen(passphrase), (const unsigned char *)ssid, ssid_len, 4096, 32, pmk);
    if (ret != 0) {
        ESP_LOGE("CRYPTO", "PBKDF2 failed: -0x%04X", -ret);
        return ret;
    }
    return 0;
}

static void calculate_ptk(const uint8_t *pmk, const uint8_t *mac_ap, const uint8_t *mac_sta,
                          const uint8_t *anonce, const uint8_t *snonce, 
                          uint8_t *ptk, int algorithm) 
{
    /* * OTTIMIZZAZIONE RAM: Abbiamo rimosso input[128].
     * Il PRF del supplicant fa l'assemblaggio internamente. Risparmiamo ~130 byte di Stack RAM.
     */
    uint8_t data[76];

    // Min(MAC_AP, MAC_STA) || Max(MAC_AP, MAC_STA)
    if (memcmp(mac_ap, mac_sta, 6) < 0) {
        memcpy(data, mac_ap, 6); memcpy(data + 6, mac_sta, 6);
    } else {
        memcpy(data, mac_sta, 6); memcpy(data + 6, mac_ap, 6);
    }

    // Min(ANonce, SNonce) || Max(ANonce, SNonce)
    if (memcmp(anonce, snonce, 32) < 0) {
        memcpy(data + 12, anonce, 32); memcpy(data + 44, snonce, 32);
    } else {
        memcpy(data + 12, snonce, 32); memcpy(data + 44, anonce, 32);
    }
    
    // Generazione PTK usando le Pseudorandom Functions native del firmware
    if (algorithm == PTK_ALG_SHA256) {
        sha256_prf(pmk, 32, "Pairwise key expansion", data, sizeof(data), ptk, WPA_PTK_LEN);
    } else {
        sha1_prf(pmk, 32, "Pairwise key expansion", data, sizeof(data), ptk, WPA_PTK_LEN);
    }
}

static void calculate_mic(const uint8_t *ptk, const uint8_t *eapol, size_t eapol_len, uint8_t *mic, uint8_t key_descriptor) 
{
    /* * OTTIMIZZAZIONE RAM: Abbiamo rimosso mbedtls_cipher_context e mbedtls_md_context.
     * Risparmiamo altri ~150 byte di Stack RAM e snelliamo brutalmente l'esecuzione.
     */
    if (key_descriptor == 1) {
        hmac_md5(ptk, 16, eapol, eapol_len, mic);
    } 
    else if (key_descriptor == 2) {
        hmac_sha1(ptk, 16, eapol, eapol_len, mic);
    } 
    else if (key_descriptor == 3) {
        omac1_aes_128(ptk, eapol, eapol_len, mic);
    }
}

static void calculate_pmkid(const uint8_t *pmk, const uint8_t *mac_ap, const uint8_t *mac_sta, uint8_t *pmkid) 
{
    uint8_t data[20];
    memcpy(data, "PMK Name", 8);
    memcpy(data + 8, mac_ap, 6);
    memcpy(data + 14, mac_sta, 6);

    uint8_t hash[20];
    hmac_sha1(pmk, 32, data, sizeof(data), hash);
    memcpy(pmkid, hash, PMKID_LEN);
}


bool verify_password(const char *passphrase, const char *ssid, size_t ssid_len,
                     const uint8_t *mac_ap, const uint8_t *mac_sta,
                     const uint8_t *anonce, const uint8_t *snonce,
                     const uint8_t *eapol, size_t eapol_len,
                     const uint8_t *expected_mic, uint8_t key_descriptor) 
{
    int error;
    uint8_t pmk[32] = { 0 }; 
    uint8_t ptk[WPA_PTK_LEN] = { 0 }; 
    uint8_t calculated_mic[16] = { 0 };
    uint8_t zero_mic_eapol[256] = { 0 }; // Buffer per EAPOL con MIC azzerato

    if (eapol_len < 97 || eapol_len > sizeof(zero_mic_eapol)) {
        ESP_LOGE(TAG, "Invalid M2 EAPOL Length: %zu", eapol_len);
        return false;
    }

    error = calculate_pmk(passphrase, ssid, ssid_len, pmk);
    if (error != 0) {
        return false;
    }

    int ptk_alg = (key_descriptor == 3) ? PTK_ALG_SHA256 : PTK_ALG_SHA1;
    calculate_ptk(pmk, mac_ap, mac_sta, anonce, snonce, ptk, ptk_alg);

    memcpy(zero_mic_eapol, eapol, eapol_len);
    // Azzera ESATTAMENTE i 16 byte del MIC (Offset fisso a 81 per i frame EAPOL)
    memset(zero_mic_eapol + 81, 0, 16);

    calculate_mic(ptk, zero_mic_eapol, eapol_len, calculated_mic, key_descriptor);

    bool ret = memcmp(calculated_mic, expected_mic, 16) == 0;
    if(ret == true) {
        ESP_LOGI(TAG, "Password \"%s\" verified with handshake!", passphrase);
    }
    return ret;
}

bool verify_pmkid(const char *passphrase, const char *ssid, size_t ssid_len,
                  const uint8_t *mac_ap, const uint8_t *mac_sta,
                  const uint8_t *expected_pmkid) 
{
    uint8_t pmk[32] = { 0 };  
    uint8_t pmkid[20] = { 0 };  

    calculate_pmk(passphrase, ssid, ssid_len, pmk);
    calculate_pmkid(pmk, mac_ap, mac_sta, pmkid);

    bool ret = memcmp(pmkid, expected_pmkid, PMKID_LEN) == 0;
    if(ret == true) {
        ESP_LOGI(TAG, "Password \"%s\" verified with PMKID!", passphrase);
    }
    return ret;
}