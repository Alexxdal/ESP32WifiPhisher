#include "../../src/libwifi.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#define BCAST_MAC "\xff\xff\xff\xff\xff\xff"
#define TO_MAC "\x00\x20\x91\xAA\xBB\xCC"
const unsigned char to[] = TO_MAC;
const unsigned char bcast[] = BCAST_MAC;

const unsigned char beacon[] = "\x00\x00\x18\x00\x8e\x58\x00\x00\x10\x02\x6c\x09\xa0\x00\x54\x00" \
                               "\x00\x2b\x00\x00\x9f\x61\xc9\x5c\x80\x00\x00\x00\xff\xff\xff\xff" \
                               "\xff\xff\x00\x0c\x41\x82\xb2\x55\x00\x0c\x41\x82\xb2\x55\x50\xf8" \
                               "\x89\xf1\xd4\x1b\x01\x00\x00\x00\x64\x00\x11\x04\x00\x07\x43\x6f" \
                               "\x68\x65\x72\x65\x72\x01\x08\x82\x84\x8b\x96\x24\x30\x48\x6c\x03" \
                               "\x01\x01\x05\x04\x00\x01\x00\x00\x2a\x01\x02\x2f\x01\x02\x30\x18" \
                               "\x01\x00\x00\x0f\xac\x02\x02\x00\x00\x0f\xac\x04\x00\x0f\xac\x02" \
                               "\x01\x00\x00\x0f\xac\x02\x00\x00\x32\x04\x0c\x12\x18\x60\xdd\x06" \
                               "\x00\x10\x18\x02\x00\x04\xdd\x1c\x00\x50\xf2\x01\x01\x00\x00\x50" \
                               "\xf2\x02\x02\x00\x00\x50\xf2\x04\x00\x50\xf2\x02\x01\x00\x00\x50" \
                               "\xf2\x02\x00\x00\x9f\x61\xc9\x5c";

int test_beacon_gen_full() {
    struct libwifi_beacon beacon = {0};

    int ret = libwifi_create_beacon(&beacon, bcast, to, to, "Some SSID", 11);
    if (ret != 0) {
        fprintf(stderr, "Failed to create beacon: %s\n", strerror(ret));
        return ret;
    }

    int beacon_len = libwifi_get_beacon_length(&beacon);
    if (beacon_len <= 0) {
        fprintf(stderr, "Invalid beacon length: %d\n", beacon_len);
        return beacon_len;
    }

    unsigned char *buf = malloc(beacon_len);
    if (buf == NULL) {
        fprintf(stderr, "Failed to allocate buffer\n");
        return -1;
    }

    int dump_len = libwifi_dump_beacon(&beacon, buf, beacon_len);
    if (dump_len <= 0) {
        fprintf(stderr, "Failed to dump beacon\n");
        return ret;
    }

    return 0;
}

int test_beacon_add_tag() {
    struct libwifi_beacon beacon = {0};

    int ret = libwifi_create_beacon(&beacon, bcast, to, to, "Some SSID", 11);
    if (ret != 0) {
        fprintf(stderr, "Failed to create beacon: %s\n", strerror(ret));
        return ret;
    }

    ret = libwifi_quick_add_tag(&beacon.tags,
                                TAG_VENDOR_SPECIFIC,
                                (const unsigned char *) "\x00\x11\x22\xAAHello World",
                                15);
    if (ret != 0) {
        fprintf(stderr, "Failed to add beacon tagged parameter: %s\n", strerror(ret));
        return ret;
    }

    int beacon_len = libwifi_get_beacon_length(&beacon);
    if (beacon_len <= 0) {
        fprintf(stderr, "Invalid beacon length: %d\n", beacon_len);
        return beacon_len;
    }

    unsigned char *buf = malloc(beacon_len);
    if (buf == NULL) {
        fprintf(stderr, "Failed to allocate buffer\n");
        return -1;
    }

    int dump_len = libwifi_dump_beacon(&beacon, buf, beacon_len);
    if (dump_len <= 0) {
        fprintf(stderr, "Failed to dump beacon\n");
        return ret;
    }

    return 0;
}

int test_beacon_parse() {
    struct libwifi_frame frame = {0};
    struct libwifi_bss bss = {0};

    int ret = libwifi_get_wifi_frame(&frame, beacon, sizeof(beacon), 1);
    if (ret != 0) {
        return ret;
    }

    if (frame.frame_control.type != TYPE_MANAGEMENT || frame.frame_control.subtype != SUBTYPE_BEACON) {
        return -1;
    }

    ret = libwifi_parse_beacon(&bss, &frame);
    if (ret != 0) {
        return ret;
    }

    if (strcmp(bss.ssid, "Coherer") != 0) {
        return -2;
    }

    if (bss.channel != 1) {
        return -3;
    }

    libwifi_free_bss(&bss);
    libwifi_free_wifi_frame(&frame);

    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Specify test\n");
        return -1;
    }

    if (strcmp(argv[1], "--beacon-gen-full") == 0) {
        return test_beacon_gen_full();
    } else if (strcmp(argv[1], "--beacon-gen-tags") == 0) {
        return test_beacon_add_tag();
    } else if (strcmp(argv[1], "--beacon-parse") == 0) {
        return test_beacon_parse();
    }

    return -1;
}
