#include <stdint.h>
#include <sys/types.h>

#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"

static const uint8_t radiotap_data[] = {
    0x00,
    0x00, // <-- radiotap version (ignore this)
    0x18,
    0x00, // <-- number of bytes in our header (count the number of "0x"s)

    /**
     * The next field is a bitmap of which options we are including.
     * The full list of which field is which option is in ieee80211_radiotap.h,
     * but I've chosen to include:
     *   0x00 0x01: timestamp
     *   0x00 0x02: flags
     *   0x00 0x03: rate
     *   0x00 0x04: channel
     *   0x80 0x00: tx flags (seems silly to have this AND flags, but oh well)
     */
    0x0f,
    0x80,
    0x00,
    0x00,

    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00, // <-- timestamp

    /**
     * This is the first set of flags, and we've set the bit corresponding to
     * IEEE80211_RADIOTAP_F_FCS, meaning we want the card to add a FCS at the
     * end of our buffer for us.
     */
    0x10,

    0x00, // <-- rate
    0x00,
    0x00,
    0x00,
    0x00, // <-- channel

    /**
     * This is the second set of flags, specifically related to transmissions.
     * The bit we've set is IEEE80211_RADIOTAP_F_TX_NOACK, which means the card
     * won't wait for an ACK for this frame, and that it won't retry if it
     * doesn't get one.
     */
    0x08,
    0x00,
};

void hexdump(void *data, size_t size);
