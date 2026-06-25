#ifndef PACKET_VALIDATE_H
#define PACKET_VALIDATE_H

#include "e2e/room_password_packet.h"
#include "protocol/protocol.h"
#include "server/server_rooms.h"

PacketState validate_packet_begin(uint32_t msg_len, Header* h);
PacketState validate_packet_chat(uint32_t msg_len, Header* h);
PacketState validate_packet_room_change(uint32_t msg_len, Header* h);
PacketState validate_packet_room_password(uint32_t room_id, RoomPasswordInfo* rpi);
PacketState validate_packet_room_password_rekey(uint32_t room_id, const ServerRoom* room,
                                                RoomPasswordInfo* rpi);

#endif