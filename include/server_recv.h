#ifndef SERVER_RECV_H
#define SERVER_RECV_H
#include <stdint.h>

int server_recv_pkt_room_join_begin(uint8_t* msg, uint16_t msg_len, uint32_t* out_room_id);
int server_recv_pkt_room_unlock(uint8_t* msg, uint16_t msg_len, uint32_t* out_room_id);

#endif // SERVER_RECV_H