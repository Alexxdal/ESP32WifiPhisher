#include "../../src/libwifi.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#define BCAST_MAC "\xff\xff\xff\xff\xff\xff"
#define TO_MAC "\x00\x20\x91\xAA\xBB\xCC"
#define CURRENT_AP "\x00\x20\x91\x00\x11\x22"
const unsigned char to[] = TO_MAC;
const unsigned char bcast[] = BCAST_MAC;
const unsigned char current_ap[] = CURRENT_AP;

int test_reassoc_resp_gen_full() {
    struct libwifi_reassoc_resp reassoc_resp = {0};

    int ret = libwifi_create_reassoc_resp(&reassoc_resp, bcast, to, current_ap, 11);
    if (ret != 0) {
        fprintf(stderr, "Failed to create reassoc_resp: %s\n", strerror(ret));
        return ret;
    }

    int reassoc_resp_len = libwifi_get_reassoc_resp_length(&reassoc_resp);
    if (reassoc_resp_len <= 0) {
        fprintf(stderr, "Invalid reassoc_resp length: %d\n", reassoc_resp_len);
        return reassoc_resp_len;
    }

    unsigned char *buf = malloc(reassoc_resp_len);
    if (buf == NULL) {
        fprintf(stderr, "Failed to allocate buffer\n");
        return -1;
    }

    int dump_len = libwifi_dump_reassoc_resp(&reassoc_resp, buf, reassoc_resp_len);
    if (dump_len <= 0) {
        fprintf(stderr, "Failed to dump reassoc_resp\n");
        return ret;
    }

    return 0;
}

int test_reassoc_resp_add_tag() {
    struct libwifi_reassoc_resp reassoc_resp = {0};

    int ret = libwifi_create_reassoc_resp(&reassoc_resp, bcast, to, current_ap, 11);
    if (ret != 0) {
        fprintf(stderr, "Failed to create reassoc_resp: %s\n", strerror(ret));
        return ret;
    }

    ret = libwifi_quick_add_tag(&reassoc_resp.tags, TAG_VENDOR_SPECIFIC, (const unsigned char *) "\x00\x11\x22\xAAHello World", 15);
    if (ret != 0) {
        fprintf(stderr, "Failed to add reassoc_resp tagged parameter: %s\n", strerror(ret));
        return ret;
    }

    int reassoc_resp_len = libwifi_get_reassoc_resp_length(&reassoc_resp);
    if (reassoc_resp_len <= 0) {
        fprintf(stderr, "Invalid reassoc_resp length: %d\n", reassoc_resp_len);
        return reassoc_resp_len;
    }

    unsigned char *buf = malloc(reassoc_resp_len);
    if (buf == NULL) {
        fprintf(stderr, "Failed to allocate buffer\n");
        return -1;
    }

    int dump_len = libwifi_dump_reassoc_resp(&reassoc_resp, buf, reassoc_resp_len);
    if (dump_len <= 0) {
        fprintf(stderr, "Failed to dump reassoc_resp\n");
        return ret;
    }

    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Specify test\n");
        return -1;
    }

    if (strcmp(argv[1], "--reassoc_resp-gen-full") == 0) {
        return test_reassoc_resp_gen_full();
    } else if (strcmp(argv[1], "--reassoc_resp-gen-tags") == 0) {
        return test_reassoc_resp_add_tag();
    }

    return -1;
}
