#ifndef CLIENT_RECV_H
#define CLIENT_RECV_H

#include "e2e/client_room_session.h"
#include "e2e/room_password_packet.h"
#include "transport/connection.h"

#include <stdint.h>

int client_recv_pkt_room_password_info(uint8_t* msg, uint16_t msg_len, uint32_t* out_room_id,
                                       RoomPasswordInfo* out_rpi);
int client_recv_pkt_enc_chat(Client* c, Header* h, RoomSession* room, uint8_t* msg,
                             uint16_t msg_len, uint8_t** out_msg, uint16_t* out_msg_len);

#endif