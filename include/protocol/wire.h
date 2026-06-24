#ifndef WIRE_H
#define WIRE_H

#include <stdint.h>

uint64_t get_u64_be(const uint8_t* p);
void     put_u64_be(uint8_t* p, uint64_t v);
uint32_t get_u32_be(const uint8_t* p);
void     put_u32_be(uint8_t* p, uint32_t v);
uint16_t get_u16_be(const uint8_t* p);
void     put_u16_be(uint8_t* p, uint16_t v);

#endif // WIRE_H
