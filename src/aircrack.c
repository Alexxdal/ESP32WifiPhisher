#include <mbedtls/md.h>
#include <mbedtls/aes.h>
#include <mbedtls/sha1.h>
#include <mbedtls/cmac.h>
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


/* Static declarations */
static void calculate_pmk(const char *passphrase, const char *ssid, size_t ssid_len, uint8_t *pmk);
static void calculate_ptk(const uint8_t *pmk, const uint8_t *mac_ap, const uint8_t *mac_sta,
                          const uint8_t *anonce, const uint8_t *snonce, 
                          uint8_t *ptk, int algorithm) ;
static void calculate_mic(const uint8_t *ptk, const uint8_t *eapol, size_t eapol_len, uint8_t *mic, uint8_t key_descriptor);
static void calculate_pmkid(const uint8_t *pmk, const uint8_t *mac_ap, const uint8_t *mac_sta, uint8_t *pmkid);


static void calculate_pmk(const char *passphrase, const char *ssid, size_t ssid_len, uint8_t *pmk) 
{
    mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA1, (const unsigned char *)passphrase, strlen(passphrase), (const unsigned char *)ssid, ssid_len, 4096, 32, pmk);
}

static void calculate_ptk(const uint8_t *pmk, const uint8_t *mac_ap, const uint8_t *mac_sta,
                          const uint8_t *anonce, const uint8_t *snonce, 
                          uint8_t *ptk, int algorithm) 
{
    const char *label = "Pairwise key expansion";
    uint8_t data[76] = { 0 };
    uint8_t input[128] = { 0 };
    size_t label_len = strlen(label);

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

    uint8_t counter = 0;
    size_t bytes_generated = 0;
    
    // Setup mbedTLS in base all'algoritmo
    mbedtls_md_type_t md_type = (algorithm == PTK_ALG_SHA256) ? MBEDTLS_MD_SHA256 : MBEDTLS_MD_SHA1;
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(md_type);
    size_t hash_len = mbedtls_md_get_size(info); // 20 per SHA1, 32 per SHA256
    uint8_t temp[32]; // Max size (SHA256)

    while (bytes_generated < WPA_PTK_LEN) {
        // Label + 0x00 + Data + Counter
        memcpy(input, label, label_len);
        input[label_len] = 0x00;
        memcpy(input + label_len + 1, data, sizeof(data));
        input[label_len + 1 + sizeof(data)] = counter;

        size_t input_len = label_len + 1 + sizeof(data) + 1;

        mbedtls_md_context_t ctx;
        mbedtls_md_init(&ctx);
        mbedtls_md_setup(&ctx, info, 1);
        mbedtls_md_hmac_starts(&ctx, pmk, 32);
        mbedtls_md_hmac_update(&ctx, input, input_len);
        mbedtls_md_hmac_finish(&ctx, temp);
        mbedtls_md_free(&ctx);

        size_t bytes_to_copy = (WPA_PTK_LEN - bytes_generated > hash_len) ? hash_len : WPA_PTK_LEN - bytes_generated;
        memcpy(ptk + bytes_generated, temp, bytes_to_copy);
        bytes_generated += bytes_to_copy;
        counter++;
    }
}

static void calculate_mic(const uint8_t *ptk, const uint8_t *eapol, size_t eapol_len, uint8_t *mic, uint8_t key_descriptor) 
{
    /* TKIP: HMAC‑MD5 */
    if (key_descriptor == 1) {
        mbedtls_md_context_t ctx;
        const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_MD5);
        mbedtls_md_init(&ctx);
        mbedtls_md_setup(&ctx, info, 1);
        mbedtls_md_hmac_starts(&ctx, ptk, 16);
        mbedtls_md_hmac_update(&ctx, eapol, eapol_len);
        mbedtls_md_hmac_finish(&ctx, mic);
        mbedtls_md_free(&ctx);
    }
    /* CCMP: HMAC‑SHA1 */
    else if (key_descriptor == 2) {
        uint8_t sha1[20];
        mbedtls_md_context_t ctx;
        const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
        mbedtls_md_init(&ctx);
        mbedtls_md_setup(&ctx, info, 1);
        mbedtls_md_hmac_starts(&ctx, ptk, 16);
        mbedtls_md_hmac_update(&ctx, eapol, eapol_len);
        mbedtls_md_hmac_finish(&ctx, sha1);
        mbedtls_md_free(&ctx);
        memcpy(mic, sha1, 16);
    } 
    /* CCMP+PMF: AES‑CMAC */
    else if (key_descriptor == 3) {
        uint8_t cmac[16];
        mbedtls_cipher_context_t ctx;
        const mbedtls_cipher_info_t *info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);
        mbedtls_cipher_init(&ctx);
        mbedtls_cipher_setup(&ctx, info);
        mbedtls_cipher_cmac_starts(&ctx, ptk, 128);
        mbedtls_cipher_cmac_update(&ctx, eapol, eapol_len);
        mbedtls_cipher_cmac_finish(&ctx, cmac);
        mbedtls_cipher_free(&ctx);
        memcpy(mic, cmac, 16);
    }
}


static void calculate_pmkid(const uint8_t *pmk, const uint8_t *mac_ap, const uint8_t *mac_sta, uint8_t *pmkid) 
{
    const char *pmk_name = "PMK Name";  // Etichetta utilizzata per generare PMKID
    uint8_t data[20] = { 0 };  // Lunghezza: 8 ("PMK Name") + 6 (MAC AP) + 6 (MAC STA)
    memcpy(data, pmk_name, 8);
    memcpy(data + 8, mac_ap, 6);
    memcpy(data + 14, mac_sta, 6);

    mbedtls_md_context_t ctx;
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);

    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, info, 1);
    mbedtls_md_hmac_starts(&ctx, pmk, 32);  // PMK come chiave HMAC
    mbedtls_md_hmac_update(&ctx, data, sizeof(data));
    mbedtls_md_hmac_finish(&ctx, pmkid);  // Il risultato è il PMKID (primi 16 byte)

    mbedtls_md_free(&ctx);
}


bool verify_password(const char *passphrase, const char *ssid, size_t ssid_len,
                     const uint8_t *mac_ap, const uint8_t *mac_sta,
                     const uint8_t *anonce, const uint8_t *snonce,
                     const uint8_t *eapol, size_t eapol_len,
                     const uint8_t *expected_mic, uint8_t key_descriptor) 
{
    uint8_t pmk[32] = { 0 }; /* Master key */
    uint8_t ptk[WPA_PTK_LEN] = { 0 }; /* Transient key */
    uint8_t calculated_mic[16] = { 0 };

    /* 1. PMK Calculation */
    calculate_pmk(passphrase, ssid, ssid_len, pmk);

    /* 2. PTK Calculation (SHA1 or SHA256) */
    int ptk_alg = (key_descriptor == 3) ? PTK_ALG_SHA256 : PTK_ALG_SHA1;
    calculate_ptk(pmk, mac_ap, mac_sta, anonce, snonce, ptk, ptk_alg);

    /* 3. MIC Calculation */
    calculate_mic(ptk, eapol, eapol_len, calculated_mic, key_descriptor);
    
    bool ret = memcmp(calculated_mic, expected_mic, 16) == 0;
    if(ret == true)
    {
        ESP_LOGI(TAG, "Password \"%s\" verified with handshake!.", passphrase);
    }
    return ret;
}


bool verify_pmkid(const char *passphrase, const char *ssid, size_t ssid_len,
                  const uint8_t *mac_ap, const uint8_t *mac_sta,
                  const uint8_t *expected_pmkid) {
    uint8_t pmk[32] = { 0 };    // PMK è lungo 32 byte
    uint8_t pmkid[20] = { 0 };  // PMKID è lungo 16 byte

    calculate_pmk(passphrase, ssid, ssid_len, pmk);
    calculate_pmkid(pmk, mac_ap, mac_sta, pmkid);

    bool ret = memcmp(pmkid, expected_pmkid, PMKID_LEN) == 0;
    if(ret == true)
    {
        ESP_LOGI(TAG, "Password \"%s\" verified with PMKID!.", passphrase);
    }
    return ret;
}