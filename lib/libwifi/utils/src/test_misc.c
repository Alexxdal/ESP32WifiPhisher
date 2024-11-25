#include <libwifi.h>
#include <libwifi/core/core.h>
#include <stdio.h>

void gen_macs() {
    printf("Getting 10 random MAC addresses:\n");
    for(int i = 0; i < 10; i++) {
        unsigned char mac[6] = {0};
        libwifi_random_mac(mac, NULL);
        printf(MACSTR "\n", MAC2STR(mac));
    }

    printf("Generating 10 random MAC addresses with 00:20:91 OUI:\n");
    for(int i = 0; i < 10; i++) {
        unsigned char mac[6] = {0};
        libwifi_random_mac(mac, (unsigned char *) "\x00\x20\x91");
        printf(MACSTR "\n", MAC2STR(mac));
    }
    printf("\n");
}

int main() {
    libwifi_dummy();

    printf("libwifi version: %s\n\n", libwifi_get_version());

    gen_macs();

    return 0;
}
