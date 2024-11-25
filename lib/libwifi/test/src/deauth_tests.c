#include "../../src/libwifi.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#define BCAST_MAC "\xff\xff\xff\xff\xff\xff"
#define TO_MAC "\x00\x20\x91\xAA\xBB\xCC"
const unsigned char to[] = TO_MAC;
const unsigned char bcast[] = BCAST_MAC;

int test_deauth_gen_full() {
    struct libwifi_deauth deauth = {0};

    int ret = libwifi_create_deauth(&deauth, bcast, to, to, REASON_STA_LEAVING);
    if (ret != 0) {
        fprintf(stderr, "Failed to create deauth: %s\n", strerror(ret));
        return ret;
    }

    int deauth_len = libwifi_get_deauth_length(&deauth);
    if (deauth_len <= 0) {
        fprintf(stderr, "Invalid deauth length: %d\n", deauth_len);
        return deauth_len;
    }

    unsigned char *buf = malloc(deauth_len);
    if (buf == NULL) {
        fprintf(stderr, "Failed to allocate buffer\n");
        return -1;
    }

    int dump_len = libwifi_dump_deauth(&deauth, buf, deauth_len);
    if (dump_len <= 0) {
        fprintf(stderr, "Failed to dump deauth\n");
        return ret;
    }

    return 0;
}

int test_deauth_add_tag() {
    struct libwifi_deauth deauth = {0};

    int ret = libwifi_create_deauth(&deauth, bcast, to, to, REASON_STA_LEAVING);
    if (ret != 0) {
        fprintf(stderr, "Failed to create deauth: %s\n", strerror(ret));
        return ret;
    }

    ret = libwifi_quick_add_tag(&deauth.tags, TAG_VENDOR_SPECIFIC, (const unsigned char *) "\x00\x11\x22\xAAHello World", 15);
    if (ret != 0) {
        fprintf(stderr, "Failed to add deauth tagged parameter: %s\n", strerror(ret));
        return ret;
    }

    int deauth_len = libwifi_get_deauth_length(&deauth);
    if (deauth_len <= 0) {
        fprintf(stderr, "Invalid deauth length: %d\n", deauth_len);
        return deauth_len;
    }

    unsigned char *buf = malloc(deauth_len);
    if (buf == NULL) {
        fprintf(stderr, "Failed to allocate buffer\n");
        return -1;
    }

    int dump_len = libwifi_dump_deauth(&deauth, buf, deauth_len);
    if (dump_len <= 0) {
        fprintf(stderr, "Failed to dump deauth\n");
        return ret;
    }

    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Specify test\n");
        return -1;
    }

    if (strcmp(argv[1], "--deauth-gen-full") == 0) {
        return test_deauth_gen_full();
    } else if (strcmp(argv[1], "--deauth-gen-tags") == 0) {
        return test_deauth_add_tag();
    }

    return -1;
}
