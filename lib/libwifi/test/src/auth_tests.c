#include "../../src/libwifi.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#define BCAST_MAC "\xff\xff\xff\xff\xff\xff"
#define TO_MAC "\x00\x20\x91\xAA\xBB\xCC"
const unsigned char to[] = TO_MAC;
const unsigned char bcast[] = BCAST_MAC;

int test_auth_gen_full() {
    struct libwifi_auth auth = {0};

    int ret = libwifi_create_auth(&auth, bcast, to, to, 0, 100, STATUS_SUCCESS);
    if (ret != 0) {
        fprintf(stderr, "Failed to create auth: %s\n", strerror(ret));
        return ret;
    }

    int auth_len = libwifi_get_auth_length(&auth);
    if (auth_len <= 0) {
        fprintf(stderr, "Invalid auth length: %d\n", auth_len);
        return auth_len;
    }

    unsigned char *buf = malloc(auth_len);
    if (buf == NULL) {
        fprintf(stderr, "Failed to allocate buffer\n");
        return -1;
    }

    int dump_len = libwifi_dump_auth(&auth, buf, auth_len);
    if (dump_len <= 0) {
        fprintf(stderr, "Failed to dump auth\n");
        return ret;
    }

    return 0;
}

int test_auth_add_tag() {
    struct libwifi_auth auth = {0};

    int ret = libwifi_create_auth(&auth, bcast, to, to, 0, 100, STATUS_SUCCESS);
    if (ret != 0) {
        fprintf(stderr, "Failed to create auth: %s\n", strerror(ret));
        return ret;
    }

    ret = libwifi_quick_add_tag(&auth.tags, TAG_VENDOR_SPECIFIC, (const unsigned char *) "\x00\x11\x22\xAAHello World", 15);
    if (ret != 0) {
        fprintf(stderr, "Failed to add auth tagged parameter: %s\n", strerror(ret));
        return ret;
    }

    int auth_len = libwifi_get_auth_length(&auth);
    if (auth_len <= 0) {
        fprintf(stderr, "Invalid auth length: %d\n", auth_len);
        return auth_len;
    }

    unsigned char *buf = malloc(auth_len);
    if (buf == NULL) {
        fprintf(stderr, "Failed to allocate buffer\n");
        return -1;
    }

    int dump_len = libwifi_dump_auth(&auth, buf, auth_len);
    if (dump_len <= 0) {
        fprintf(stderr, "Failed to dump auth\n");
        return ret;
    }

    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Specify test\n");
        return -1;
    }

    if (strcmp(argv[1], "--auth-gen-full") == 0) {
        return test_auth_gen_full();
    } else if (strcmp(argv[1], "--auth-gen-tags") == 0) {
        return test_auth_add_tag();
    }

    return -1;
}
