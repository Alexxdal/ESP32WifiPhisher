#include "../../src/libwifi.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#define BCAST_MAC "\xff\xff\xff\xff\xff\xff"
#define TO_MAC "\x00\x20\x91\xAA\xBB\xCC"
const unsigned char to[] = TO_MAC;
const unsigned char bcast[] = BCAST_MAC;

int test_disassoc_gen_full() {
    struct libwifi_disassoc disassoc = {0};

    int ret = libwifi_create_disassoc(&disassoc, bcast, to, to, REASON_STA_LEAVING);
    if (ret != 0) {
        fprintf(stderr, "Failed to create disassoc: %s\n", strerror(ret));
        return ret;
    }

    int disassoc_len = libwifi_get_disassoc_length(&disassoc);
    if (disassoc_len <= 0) {
        fprintf(stderr, "Invalid disassoc length: %d\n", disassoc_len);
        return disassoc_len;
    }

    unsigned char *buf = malloc(disassoc_len);
    if (buf == NULL) {
        fprintf(stderr, "Failed to allocate buffer\n");
        return -1;
    }

    int dump_len = libwifi_dump_disassoc(&disassoc, buf, disassoc_len);
    if (dump_len <= 0) {
        fprintf(stderr, "Failed to dump disassoc\n");
        return ret;
    }

    return 0;
}

int test_disassoc_add_tag() {
    struct libwifi_disassoc disassoc = {0};

    int ret = libwifi_create_disassoc(&disassoc, bcast, to, to, REASON_STA_LEAVING);
    if (ret != 0) {
        fprintf(stderr, "Failed to create disassoc: %s\n", strerror(ret));
        return ret;
    }

    ret = libwifi_quick_add_tag(&disassoc.tags, TAG_VENDOR_SPECIFIC, (const unsigned char *) "\x00\x11\x22\xAAHello World", 15);
    if (ret != 0) {
        fprintf(stderr, "Failed to add disassoc tagged parameter: %s\n", strerror(ret));
        return ret;
    }

    int disassoc_len = libwifi_get_disassoc_length(&disassoc);
    if (disassoc_len <= 0) {
        fprintf(stderr, "Invalid disassoc length: %d\n", disassoc_len);
        return disassoc_len;
    }

    unsigned char *buf = malloc(disassoc_len);
    if (buf == NULL) {
        fprintf(stderr, "Failed to allocate buffer\n");
        return -1;
    }

    int dump_len = libwifi_dump_disassoc(&disassoc, buf, disassoc_len);
    if (dump_len <= 0) {
        fprintf(stderr, "Failed to dump disassoc\n");
        return ret;
    }

    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Specify test\n");
        return -1;
    }

    if (strcmp(argv[1], "--disassoc-gen-full") == 0) {
        return test_disassoc_gen_full();
    } else if (strcmp(argv[1], "--disassoc-gen-tags") == 0) {
        return test_disassoc_add_tag();
    }

    return -1;
}
