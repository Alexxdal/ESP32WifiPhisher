#include "../../src/libwifi.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#define BCAST_MAC "\xff\xff\xff\xff\xff\xff"
#define TO_MAC "\x00\x20\x91\xAA\xBB\xCC"
const unsigned char to[] = TO_MAC;
const unsigned char bcast[] = BCAST_MAC;

int test_probe_req_gen_full() {
    struct libwifi_probe_req probe_req = {0};

    int ret = libwifi_create_probe_req(&probe_req, bcast, to, to, "Some SSID", 11);
    if (ret != 0) {
        fprintf(stderr, "Failed to create probe_req: %s\n", strerror(ret));
        return ret;
    }

    int probe_req_len = libwifi_get_probe_req_length(&probe_req);
    if (probe_req_len <= 0) {
        fprintf(stderr, "Invalid probe_req length: %d\n", probe_req_len);
        return probe_req_len;
    }

    unsigned char *buf = malloc(probe_req_len);
    if (buf == NULL) {
        fprintf(stderr, "Failed to allocate buffer\n");
        return -1;
    }

    int dump_len = libwifi_dump_probe_req(&probe_req, buf, probe_req_len);
    if (dump_len <= 0) {
        fprintf(stderr, "Failed to dump probe_req\n");
        return ret;
    }

    return 0;
}

int test_probe_req_add_tag() {
    struct libwifi_probe_req probe_req = {0};

    int ret = libwifi_create_probe_req(&probe_req, bcast, to, to, "Some SSID", 11);
    if (ret != 0) {
        fprintf(stderr, "Failed to create probe_req: %s\n", strerror(ret));
        return ret;
    }

    ret = libwifi_quick_add_tag(&probe_req.tags, TAG_VENDOR_SPECIFIC, (const unsigned char *) "\x00\x11\x22\xAAHello World", 15);
    if (ret != 0) {
        fprintf(stderr, "Failed to add probe_req tagged parameter: %s\n", strerror(ret));
        return ret;
    }

    int probe_req_len = libwifi_get_probe_req_length(&probe_req);
    if (probe_req_len <= 0) {
        fprintf(stderr, "Invalid probe_req length: %d\n", probe_req_len);
        return probe_req_len;
    }

    unsigned char *buf = malloc(probe_req_len);
    if (buf == NULL) {
        fprintf(stderr, "Failed to allocate buffer\n");
        return -1;
    }

    int dump_len = libwifi_dump_probe_req(&probe_req, buf, probe_req_len);
    if (dump_len <= 0) {
        fprintf(stderr, "Failed to dump probe_req\n");
        return ret;
    }

    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Specify test\n");
        return -1;
    }

    if (strcmp(argv[1], "--probe_req-gen-full") == 0) {
        return test_probe_req_gen_full();
    } else if (strcmp(argv[1], "--probe_req-gen-tags") == 0) {
        return test_probe_req_add_tag();
    }

    return -1;
}
