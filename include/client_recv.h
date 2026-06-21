#ifndef CLIENT_RECV_H
#define CLIENT_RECV_H
#include "room_password.h"
#include <stdint.h>

int client_recv_pkt_room_password_info(uint8_t* msg, uint16_t msg_len, uint32_t* out_room_id,
                                       RoomPasswordInfo* out_rpi);

#endif