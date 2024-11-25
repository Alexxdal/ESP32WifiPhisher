#include "../../src/libwifi.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#define BCAST_MAC "\xff\xff\xff\xff\xff\xff"
#define TO_MAC "\x00\x20\x91\xAA\xBB\xCC"
const unsigned char to[] = TO_MAC;
const unsigned char bcast[] = BCAST_MAC;

int test_probe_resp_gen_full() {
    struct libwifi_probe_resp probe_resp = {0};

    int ret = libwifi_create_probe_resp(&probe_resp, bcast, to, to, "Some SSID", 11);
    if (ret != 0) {
        fprintf(stderr, "Failed to create probe_resp: %s\n", strerror(ret));
        return ret;
    }

    int probe_resp_len = libwifi_get_probe_resp_length(&probe_resp);
    if (probe_resp_len <= 0) {
        fprintf(stderr, "Invalid probe_resp length: %d\n", probe_resp_len);
        return probe_resp_len;
    }

    unsigned char *buf = malloc(probe_resp_len);
    if (buf == NULL) {
        fprintf(stderr, "Failed to allocate buffer\n");
        return -1;
    }

    int dump_len = libwifi_dump_probe_resp(&probe_resp, buf, probe_resp_len);
    if (dump_len <= 0) {
        fprintf(stderr, "Failed to dump probe_resp\n");
        return ret;
    }

    return 0;
}

int test_probe_resp_add_tag() {
    struct libwifi_probe_resp probe_resp = {0};

    int ret = libwifi_create_probe_resp(&probe_resp, bcast, to, to, "Some SSID", 11);
    if (ret != 0) {
        fprintf(stderr, "Failed to create probe_resp: %s\n", strerror(ret));
        return ret;
    }

    ret = libwifi_quick_add_tag(&probe_resp.tags, TAG_VENDOR_SPECIFIC, (const unsigned char *) "\x00\x11\x22\xAAHello World", 15);
    if (ret != 0) {
        fprintf(stderr, "Failed to add probe_resp tagged parameter: %s\n", strerror(ret));
        return ret;
    }

    int probe_resp_len = libwifi_get_probe_resp_length(&probe_resp);
    if (probe_resp_len <= 0) {
        fprintf(stderr, "Invalid probe_resp length: %d\n", probe_resp_len);
        return probe_resp_len;
    }

    unsigned char *buf = malloc(probe_resp_len);
    if (buf == NULL) {
        fprintf(stderr, "Failed to allocate buffer\n");
        return -1;
    }

    int dump_len = libwifi_dump_probe_resp(&probe_resp, buf, probe_resp_len);
    if (dump_len <= 0) {
        fprintf(stderr, "Failed to dump probe_resp\n");
        return ret;
    }

    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Specify test\n");
        return -1;
    }

    if (strcmp(argv[1], "--probe_resp-gen-full") == 0) {
        return test_probe_resp_gen_full();
    } else if (strcmp(argv[1], "--probe_resp-gen-tags") == 0) {
        return test_probe_resp_add_tag();
    }

    return -1;
}
