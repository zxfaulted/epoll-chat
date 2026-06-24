
#ifndef PACKET_PARSE_H
#define PACKET_PARSE_H
#include <stdint.h>

int packet_parse_auth_register_ok(const uint8_t* msg, uint32_t msg_len, uint32_t* out_client_id,
                                  uint32_t* out_room_id, char out_name[]);
int packet_parse_client_id_name(const uint8_t* msg, uint32_t msg_len, uint32_t* out_client_id,
                                char name[]);
#endif // PACKET_PARSE_H