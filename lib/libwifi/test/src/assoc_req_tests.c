#include "../../src/libwifi.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#define BCAST_MAC "\xff\xff\xff\xff\xff\xff"
#define TO_MAC "\x00\x20\x91\xAA\xBB\xCC"
const unsigned char to[] = TO_MAC;
const unsigned char bcast[] = BCAST_MAC;

int test_assoc_req_gen_full() {
    struct libwifi_assoc_req assoc_req = {0};

    int ret = libwifi_create_assoc_req(&assoc_req, bcast, to, to, "Some SSID", 11);
    if (ret != 0) {
        fprintf(stderr, "Failed to create assoc_req: %s\n", strerror(ret));
        return ret;
    }

    int assoc_req_len = libwifi_get_assoc_req_length(&assoc_req);
    if (assoc_req_len <= 0) {
        fprintf(stderr, "Invalid assoc_req length: %d\n", assoc_req_len);
        return assoc_req_len;
    }

    unsigned char *buf = malloc(assoc_req_len);
    if (buf == NULL) {
        fprintf(stderr, "Failed to allocate buffer\n");
        return -1;
    }

    int dump_len = libwifi_dump_assoc_req(&assoc_req, buf, assoc_req_len);
    if (dump_len <= 0) {
        fprintf(stderr, "Failed to dump assoc_req\n");
        return ret;
    }

    return 0;
}

int test_assoc_req_add_tag() {
    struct libwifi_assoc_req assoc_req = {0};

    int ret = libwifi_create_assoc_req(&assoc_req, bcast, to, to, "Some SSID", 11);
    if (ret != 0) {
        fprintf(stderr, "Failed to create assoc_req: %s\n", strerror(ret));
        return ret;
    }

    ret = libwifi_quick_add_tag(&assoc_req.tags, TAG_VENDOR_SPECIFIC, (const unsigned char *) "\x00\x11\x22\xAAHello World", 15);
    if (ret != 0) {
        fprintf(stderr, "Failed to add assoc_req tagged parameter: %s\n", strerror(ret));
        return ret;
    }

    int assoc_req_len = libwifi_get_assoc_req_length(&assoc_req);
    if (assoc_req_len <= 0) {
        fprintf(stderr, "Invalid assoc_req length: %d\n", assoc_req_len);
        return assoc_req_len;
    }

    unsigned char *buf = malloc(assoc_req_len);
    if (buf == NULL) {
        fprintf(stderr, "Failed to allocate buffer\n");
        return -1;
    }

    int dump_len = libwifi_dump_assoc_req(&assoc_req, buf, assoc_req_len);
    if (dump_len <= 0) {
        fprintf(stderr, "Failed to dump assoc_req\n");
        return ret;
    }

    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Specify test\n");
        return -1;
    }

    if (strcmp(argv[1], "--assoc_req-gen-full") == 0) {
        return test_assoc_req_gen_full();
    } else if (strcmp(argv[1], "--assoc_req-gen-tags") == 0) {
        return test_assoc_req_add_tag();
    }

    return -1;
}
