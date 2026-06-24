#ifndef PROTOCOL_DEBUG_H
#define PROTOCOL_DEBUG_H

#include "protocol/protocol.h"

const char* packet_type_str(PacketType type);
int         payload_to_str(const uint8_t payload[], size_t len, char out[], size_t out_cap);
const char* packet_state_str(PacketState st);

#endif // PROTOCOL_DEBUG_H