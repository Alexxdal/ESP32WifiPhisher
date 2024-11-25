#include "../../src/libwifi.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#define BCAST_MAC "\xff\xff\xff\xff\xff\xff"
#define TO_MAC "\x00\x20\x91\xAA\xBB\xCC"
const unsigned char to[] = TO_MAC;
const unsigned char bcast[] = BCAST_MAC;

int test_timing_ad_gen_full() {
    struct libwifi_timing_advert time_ad = {0};
    struct libwifi_timing_advert_fields ad_fields = {0};

    ad_fields.timing_capabilities = 2;
    memcpy(ad_fields.time_error, "\xCC\xCC\xCC\xCC\xCC", 5);
    memcpy(ad_fields.time_update, "\xBB", 1);
    memcpy(ad_fields.time_value,
          "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA", 10);

    int ret = libwifi_create_timing_advert(&time_ad, bcast, to, to, &ad_fields, "GB", -56, -56, -30, -20);
    if (ret != 0) {
        fprintf(stderr, "Failed to create timing advert\n");
        return ret;
    }

    unsigned char *buf = NULL;
    size_t buf_len = libwifi_get_timing_advert_length(&time_ad);
    buf = malloc(buf_len);
    if (buf == NULL) {
        fprintf(stderr, "Failed to create buffer\n");
        return -1;
    }
    printf("buf_len: %zu\n", buf_len);

    ret = libwifi_dump_timing_advert(&time_ad, buf, buf_len);
    if (ret < 0) {
        fprintf(stderr, "Failed to dump advert");
        return ret;
    }

    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Specify test\n");
        return -1;
    }

    if (strcmp(argv[1], "--timing_ad-gen-full") == 0) {
        return test_timing_ad_gen_full();
    }

    return -1;
}
