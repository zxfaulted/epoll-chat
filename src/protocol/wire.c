#include "protocol/wire.h"

#include "common/types.h"

void put_u16_be(uint8_t* p, uint16_t v)
{
    p[0] = (uint8_t)((v >> 8) & 0xFF);
    p[1] = (uint8_t)(v & 0xFF);
}

uint16_t get_u16_be(const uint8_t* p)
{
    return (uint16_t)p[0] << 8 | (uint16_t)p[1];
}

void put_u32_be(uint8_t* p, uint32_t v)
{
    p[0] = (uint8_t)((v >> 24) & 0xFF);
    p[1] = (uint8_t)((v >> 16) & 0xFF);
    p[2] = (uint8_t)((v >> 8) & 0xFF);
    p[3] = (uint8_t)(v & 0xFF);
}

uint32_t get_u32_be(const uint8_t* p)
{
    return ((uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | (uint32_t)p[3]);
}

void put_u64_be(uint8_t* p, uint64_t v)
{
    p[0] = (uint8_t)((v >> 56) & 0xFF);
    p[1] = (uint8_t)((v >> 48) & 0xFF);
    p[2] = (uint8_t)((v >> 40) & 0xFF);
    p[3] = (uint8_t)((v >> 32) & 0xFF);
    p[4] = (uint8_t)((v >> 24) & 0xFF);
    p[5] = (uint8_t)((v >> 16) & 0xFF);
    p[6] = (uint8_t)((v >> 8) & 0xFF);
    p[7] = (uint8_t)(v & 0xFF);
}

uint64_t get_u64_be(const uint8_t* p)
{
    return ((uint64_t)p[0] << 56 | (uint64_t)p[1] << 48 | (uint64_t)p[2] << 40 |
            (uint64_t)p[3] << 32 | (uint64_t)p[4] << 24 | (uint64_t)p[5] << 16 |
            (uint64_t)p[6] << 8 | (uint64_t)p[7]);
}
