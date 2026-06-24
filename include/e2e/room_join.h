#ifndef ROOM_JOIN_H
#define ROOM_JOIN_H
#include "e2e/e2e_protocol.h"

int build_pkt_join_begin_payload(uint8_t* out_msg, uint16_t* out_msg_len, uint32_t room_id);
int parse_pkt_join_begin_payload(uint8_t* msg, uint16_t msg_len, uint32_t* out_room_id);

#endif // ROOM_JOIN_H
