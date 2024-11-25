#include "../../src/libwifi.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#define BCAST_MAC  "\xff\xff\xff\xff\xff\xff"
#define TO_MAC     "\x00\x20\x91\xAA\xBB\xCC"
#define CURRENT_AP "\x00\x20\x91\x00\x11\x22"
const unsigned char to[] = TO_MAC;
const unsigned char bcast[] = BCAST_MAC;
const unsigned char current_ap[] = CURRENT_AP;

int test_reassoc_req_gen_full() {
    struct libwifi_reassoc_req reassoc_req = {0};

    int ret = libwifi_create_reassoc_req(&reassoc_req, bcast, to, to, current_ap, "Some SSID", 11);
    if (ret != 0) {
        fprintf(stderr, "Failed to create reassoc_req: %s\n", strerror(ret));
        return ret;
    }

    int reassoc_req_len = libwifi_get_reassoc_req_length(&reassoc_req);
    if (reassoc_req_len <= 0) {
        fprintf(stderr, "Invalid reassoc_req length: %d\n", reassoc_req_len);
        return reassoc_req_len;
    }

    unsigned char *buf = malloc(reassoc_req_len);
    if (buf == NULL) {
        fprintf(stderr, "Failed to allocate buffer\n");
        return -1;
    }

    int dump_len = libwifi_dump_reassoc_req(&reassoc_req, buf, reassoc_req_len);
    if (dump_len <= 0) {
        fprintf(stderr, "Failed to dump reassoc_req\n");
        return ret;
    }

    return 0;
}

int test_reassoc_req_add_tag() {
    struct libwifi_reassoc_req reassoc_req = {0};

    int ret = libwifi_create_reassoc_req(&reassoc_req, bcast, to, to, current_ap, "Some SSID", 11);
    if (ret != 0) {
        fprintf(stderr, "Failed to create reassoc_req: %s\n", strerror(ret));
        return ret;
    }

    ret = libwifi_quick_add_tag(&reassoc_req.tags, TAG_VENDOR_SPECIFIC, (const unsigned char *) "\x00\x11\x22\xAAHello World", 15);
    if (ret != 0) {
        fprintf(stderr, "Failed to add reassoc_req tagged parameter: %s\n", strerror(ret));
        return ret;
    }

    int reassoc_req_len = libwifi_get_reassoc_req_length(&reassoc_req);
    if (reassoc_req_len <= 0) {
        fprintf(stderr, "Invalid reassoc_req length: %d\n", reassoc_req_len);
        return reassoc_req_len;
    }

    unsigned char *buf = malloc(reassoc_req_len);
    if (buf == NULL) {
        fprintf(stderr, "Failed to allocate buffer\n");
        return -1;
    }

    int dump_len = libwifi_dump_reassoc_req(&reassoc_req, buf, reassoc_req_len);
    if (dump_len <= 0) {
        fprintf(stderr, "Failed to dump reassoc_req\n");
        return ret;
    }

    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Specify test\n");
        return -1;
    }

    if (strcmp(argv[1], "--reassoc_req-gen-full") == 0) {
        return test_reassoc_req_gen_full();
    } else if (strcmp(argv[1], "--reassoc_req-gen-tags") == 0) {
        return test_reassoc_req_add_tag();
    }

    return -1;
}
