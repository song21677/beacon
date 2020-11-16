#include <stdint.h>
#include "mac.h"

struct beacon
{
    Mac address1;
    Mac address2;
    Mac address3;
    uint8_t frag:4;
    uint16_t seq:12;
};

