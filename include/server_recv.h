#ifndef SERVER_RECV_H
#define SERVER_RECV_H

#include "room_password.h"
#include <stdint.h>

int server_recv_pkt_room_join_begin(uint8_t* msg, uint16_t msg_len, uint32_t* out_room_id);
int server_recv_pkt_room_unlock(uint8_t* msg, uint16_t msg_len, uint32_t* out_room_id,
                                uint64_t* out_epoch,
                                uint8_t   out_verifier[ROOM_PASSWORD_VERIFIER_LEN]);

#endif // SERVER_RECV_H