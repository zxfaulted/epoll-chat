#ifndef PACKET_VALIDATE_H
#define PACKET_VALIDATE_H

#include "protocol/protocol.h"

PacketState validate_packet_begin(uint32_t msg_len, Header* h);
PacketState validate_packet_chat(uint32_t msg_len, Header* h);
PacketState validate_packet_room_change(uint32_t msg_len, Header* h);

#endif