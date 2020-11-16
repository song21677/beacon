#ifndef BEACON
#define BEACON
#include <stdint.h>
#include "mac.h"
#include "dot11.h"

struct beacon : dot11
{
    Mac da;
    Mac sa;
    Mac bssid;
    uint8_t frag:4;
    uint16_t seq:12;

    #pragma pack(push, 1)
    struct Fix {
       uint64_t timestamp;
       uint16_t binterval;
       uint16_t cap;
    } fix_;
    #pragma pack(pop)

    struct Tag {
        uint8_t num;
        uint8_t length;
        Tag* next() {
            char* res = (char*)this;
            res += sizeof(Tag) + this->length;
            return PTag(res);
        }
    } tag_;

    typedef Tag *PTag;

    Tag* tag() {
        char* p = (char *)(this);
        p += sizeof(beacon);
        return PTag(p);
    }

    enum: uint8_t {
        Ssid = 0,
        Supported = 1,
        Traffic = 5
    };

    struct Traffic : Tag {
        uint8_t count;
        uint8_t period;
        uint8_t control;
        uint8_t bitmap;
    };
};


#endif

