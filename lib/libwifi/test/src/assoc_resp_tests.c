#include "../../src/libwifi.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#define BCAST_MAC "\xff\xff\xff\xff\xff\xff"
#define TO_MAC "\x00\x20\x91\xAA\xBB\xCC"
const unsigned char to[] = TO_MAC;
const unsigned char bcast[] = BCAST_MAC;

int test_assoc_resp_gen_full() {
    struct libwifi_assoc_resp assoc_resp = {0};

    int ret = libwifi_create_assoc_resp(&assoc_resp, bcast, to, to, 11);
    if (ret != 0) {
        fprintf(stderr, "Failed to create assoc_resp: %s\n", strerror(ret));
        return ret;
    }

    int assoc_resp_len = libwifi_get_assoc_resp_length(&assoc_resp);
    if (assoc_resp_len <= 0) {
        fprintf(stderr, "Invalid assoc_resp length: %d\n", assoc_resp_len);
        return assoc_resp_len;
    }

    unsigned char *buf = malloc(assoc_resp_len);
    if (buf == NULL) {
        fprintf(stderr, "Failed to allocate buffer\n");
        return -1;
    }

    int dump_len = libwifi_dump_assoc_resp(&assoc_resp, buf, assoc_resp_len);
    if (dump_len <= 0) {
        fprintf(stderr, "Failed to dump assoc_resp\n");
        return ret;
    }

    return 0;
}

int test_assoc_resp_add_tag() {
    struct libwifi_assoc_resp assoc_resp = {0};

    int ret = libwifi_create_assoc_resp(&assoc_resp, bcast, to, to, 11);
    if (ret != 0) {
        fprintf(stderr, "Failed to create assoc_resp: %s\n", strerror(ret));
        return ret;
    }

    ret = libwifi_quick_add_tag(&assoc_resp.tags, TAG_VENDOR_SPECIFIC, (const unsigned char *) "\x00\x11\x22\xAAHello World", 15);
    if (ret != 0) {
        fprintf(stderr, "Failed to add assoc_resp tagged parameter: %s\n", strerror(ret));
        return ret;
    }

    int assoc_resp_len = libwifi_get_assoc_resp_length(&assoc_resp);
    if (assoc_resp_len <= 0) {
        fprintf(stderr, "Invalid assoc_resp length: %d\n", assoc_resp_len);
        return assoc_resp_len;
    }

    unsigned char *buf = malloc(assoc_resp_len);
    if (buf == NULL) {
        fprintf(stderr, "Failed to allocate buffer\n");
        return -1;
    }

    int dump_len = libwifi_dump_assoc_resp(&assoc_resp, buf, assoc_resp_len);
    if (dump_len <= 0) {
        fprintf(stderr, "Failed to dump assoc_resp\n");
        return ret;
    }

    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Specify test\n");
        return -1;
    }

    if (strcmp(argv[1], "--assoc_resp-gen-full") == 0) {
        return test_assoc_resp_gen_full();
    } else if (strcmp(argv[1], "--assoc_resp-gen-tags") == 0) {
        return test_assoc_resp_add_tag();
    }

    return -1;
}
