#ifndef RADIOTAP
#define RADIOTAP
#include <cstdint>

struct radiotap {
    uint8_t ver;
    uint8_t pad;
    uint16_t len;
    uint32_t present;
};

#endif
